//! Tree-sitter engine for the static phase (v1 `static/ast_analysis`):
//! per-function metrics, the C implicit-unsafe surface, Rust
//! explicit-unsafe sites with purpose classification, and AST-derived
//! LOC (code/comment/blank per file) — every static number traces to
//! one declared parser instead of a cloc/tokei side-channel. Queries
//! are ported verbatim from v1 so the paper's counts reproduce; bump
//! [`super::AST_RECIPE`] when they change.

use std::fmt;
use std::fs;
use std::path::Path;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor};

const C_FUNC: &str = r#"
[
  (function_definition
    declarator: (function_declarator
      declarator: (identifier) @name)) @func
  (function_definition
    declarator: (pointer_declarator
      declarator: (function_declarator
        declarator: (identifier) @name))) @func
]
"#;

const C_ALLOC: &str = r#"
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(kmalloc|kzalloc|kcalloc|krealloc|kvmalloc|devm_kmalloc|devm_kzalloc)$"))
"#;

const C_FREE: &str = r#"
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(kfree|kvfree|devm_kfree|kfree_rcu)$"))
"#;

const C_MEMOP: &str = r#"
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(memcpy|memset|memmove|copy_from_user|copy_to_user|strncpy|strlcpy)$"))
"#;

const C_CAST: &str = "(cast_expression) @cast";
const C_DEREF: &str = "(pointer_expression) @deref";
const C_ARROW: &str = r#"(field_expression operator: "->") @arrow"#;
const C_BRANCH: &str = r#"
[
  (if_statement)
  (for_statement)
  (while_statement)
  (do_statement)
  (case_statement)
  (conditional_expression)
] @branch
"#;
const C_COMMENT: &str = "(comment) @comment";

const RS_FUNC: &str = "(function_item name: (identifier) @name) @func";
const RS_UNSAFE_BLOCK: &str = "(unsafe_block) @unsafe";
// "unsafe" is an anonymous keyword token — must be quoted in queries.
const RS_UNSAFE_FN: &str = r#"
(function_item
  (function_modifiers "unsafe")
  name: (identifier) @name) @func
"#;
// v1 counted only unsafe blocks and fns; `unsafe impl` (Send/Sync
// and trait-contract assertions) is unsafe surface too and the
// abstraction layer is full of it.
const RS_UNSAFE_IMPL: &str = r#"(impl_item "unsafe") @impl"#;
const RS_CALL: &str = "(call_expression function: (_) @callee)";
const RS_BRANCH: &str = r#"
[
  (if_expression)
  (for_expression)
  (while_expression)
  (loop_expression)
  (match_arm)
] @branch
"#;
const RS_COMMENT: &str = "[(line_comment) (block_comment)] @comment";

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub driver: String,
    pub file: String,
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub line_count: usize,
    pub complexity: usize,
}

#[derive(Debug, Clone)]
pub struct UnsafeSite {
    /// "driver" | "abstraction"
    pub source: String,
    pub file: String,
    pub line: usize,
    pub end_line: usize,
    /// "unsafe_block" | "unsafe_fn"
    pub node_type: &'static str,
    pub preview: String,
    /// Mixed-Methods Unsafe Rust taxonomy (arXiv 2404.02230):
    /// ffi, ptr_deref, asm, transmute, static_mut, perf, other.
    pub purpose: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct Density {
    pub driver: String,
    pub file: String,
    pub language: &'static str,
    pub total_functions: usize,
    pub unsafe_blocks: usize,
    pub unsafe_fns: usize,
    pub unsafe_impls: usize,
    pub ptr_derefs: usize,
    pub alloc_calls: usize,
    pub free_calls: usize,
    pub memop_calls: usize,
    pub cast_exprs: usize,
}

#[derive(Debug, Clone)]
pub struct Loc {
    pub driver: String,
    pub file: String,
    pub language: &'static str,
    pub blank: usize,
    pub comment: usize,
    pub code: usize,
}

#[derive(Debug, Default)]
pub struct Results {
    pub functions: Vec<FunctionInfo>,
    pub sites: Vec<UnsafeSite>,
    pub densities: Vec<Density>,
    pub loc: Vec<Loc>,
}

pub struct Analyzer {
    c: Language,
    rs: Language,
    c_func: Query,
    c_alloc: Query,
    c_free: Query,
    c_memop: Query,
    c_cast: Query,
    c_deref: Query,
    c_arrow: Query,
    c_branch: Query,
    c_comment: Query,
    rs_func: Query,
    rs_unsafe_block: Query,
    rs_unsafe_fn: Query,
    rs_unsafe_impl: Query,
    rs_call: Query,
    rs_branch: Query,
    rs_comment: Query,
}

impl Analyzer {
    pub fn new() -> Result<Self, Error> {
        let c: Language = tree_sitter_c::LANGUAGE.into();
        let rs: Language = tree_sitter_rust::LANGUAGE.into();
        let query = |language: &Language, source: &str| {
            Query::new(language, source).map_err(|err| Error::Query(err.to_string()))
        };
        Ok(Self {
            c_func: query(&c, C_FUNC)?,
            c_alloc: query(&c, C_ALLOC)?,
            c_free: query(&c, C_FREE)?,
            c_memop: query(&c, C_MEMOP)?,
            c_cast: query(&c, C_CAST)?,
            c_deref: query(&c, C_DEREF)?,
            c_arrow: query(&c, C_ARROW)?,
            c_branch: query(&c, C_BRANCH)?,
            c_comment: query(&c, C_COMMENT)?,
            rs_func: query(&rs, RS_FUNC)?,
            rs_unsafe_block: query(&rs, RS_UNSAFE_BLOCK)?,
            rs_unsafe_fn: query(&rs, RS_UNSAFE_FN)?,
            rs_unsafe_impl: query(&rs, RS_UNSAFE_IMPL)?,
            rs_call: query(&rs, RS_CALL)?,
            rs_branch: query(&rs, RS_BRANCH)?,
            rs_comment: query(&rs, RS_COMMENT)?,
            c,
            rs,
        })
    }

    pub fn analyze_c_file(
        &self,
        path: &Path,
        driver: &str,
        results: &mut Results,
    ) -> Result<(), Error> {
        let source = fs::read(path).map_err(|err| Error::Io(path.display().to_string(), err))?;
        let tree = parse(&self.c, &source, path)?;
        let root = tree.root_node();
        let file = file_name(path);

        let functions = self.functions(&self.c_func, &self.c_branch, root, &source, driver, &file);
        let total_functions = functions.len();
        results.functions.extend(functions);
        results.densities.push(Density {
            driver: driver.to_owned(),
            file: file.clone(),
            language: "C",
            total_functions,
            ptr_derefs: self.count(&self.c_deref, root, &source)
                + self.count(&self.c_arrow, root, &source),
            alloc_calls: self.count(&self.c_alloc, root, &source),
            free_calls: self.count(&self.c_free, root, &source),
            memop_calls: self.count(&self.c_memop, root, &source),
            cast_exprs: self.count(&self.c_cast, root, &source),
            ..Default::default()
        });
        results
            .loc
            .push(self.loc(&self.c_comment, root, &source, driver, &file, "C"));
        Ok(())
    }

    pub fn analyze_rs_file(
        &self,
        path: &Path,
        driver: &str,
        source_tag: &str,
        results: &mut Results,
    ) -> Result<(), Error> {
        let source = fs::read(path).map_err(|err| Error::Io(path.display().to_string(), err))?;
        let tree = parse(&self.rs, &source, path)?;
        let root = tree.root_node();
        let file = if source_tag == "driver" {
            file_name(path)
        } else {
            path.display().to_string()
        };

        let functions =
            self.functions(&self.rs_func, &self.rs_branch, root, &source, driver, &file);
        let total_functions = functions.len();
        results.functions.extend(functions);

        let mut unsafe_blocks = 0;
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&self.rs_unsafe_block, root, source.as_slice());
        while let Some(found) = matches.next() {
            let Some(node) = found.captures().first().map(|capture| capture.node) else {
                continue;
            };
            unsafe_blocks += 1;
            let text = node_text(node, &source);
            results.sites.push(UnsafeSite {
                source: source_tag.to_owned(),
                file: file.clone(),
                line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                node_type: "unsafe_block",
                preview: preview(&text),
                purpose: self.classify_unsafe(node, &source),
            });
        }

        let mut unsafe_impls = 0;
        let mut matches = cursor.matches(&self.rs_unsafe_impl, root, source.as_slice());
        while let Some(found) = matches.next() {
            let Some(node) = found.captures().first().map(|capture| capture.node) else {
                continue;
            };
            unsafe_impls += 1;
            let text = node_text(node, &source);
            results.sites.push(UnsafeSite {
                source: source_tag.to_owned(),
                file: file.clone(),
                line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                node_type: "unsafe_impl",
                preview: preview(text.lines().next().unwrap_or_default()),
                purpose: self.classify_unsafe(node, &source),
            });
        }

        let mut unsafe_fns = 0;
        let mut matches = cursor.matches(&self.rs_unsafe_fn, root, source.as_slice());
        while let Some(found) = matches.next() {
            let Some(func) = capture(&self.rs_unsafe_fn, found, "func") else {
                continue;
            };
            let Some(name) = capture(&self.rs_unsafe_fn, found, "name") else {
                continue;
            };
            unsafe_fns += 1;
            results.sites.push(UnsafeSite {
                source: source_tag.to_owned(),
                file: file.clone(),
                line: func.start_position().row + 1,
                end_line: func.end_position().row + 1,
                node_type: "unsafe_fn",
                preview: format!("unsafe fn {}", node_text(name, &source)),
                purpose: self.classify_unsafe(func, &source),
            });
        }

        results.densities.push(Density {
            driver: driver.to_owned(),
            file: file.clone(),
            language: "Rust",
            total_functions,
            unsafe_blocks,
            unsafe_fns,
            unsafe_impls,
            ..Default::default()
        });
        results
            .loc
            .push(self.loc(&self.rs_comment, root, &source, driver, &file, "Rust"));
        Ok(())
    }

    fn functions(
        &self,
        func_query: &Query,
        branch_query: &Query,
        root: Node,
        source: &[u8],
        driver: &str,
        file: &str,
    ) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(func_query, root, source);
        while let Some(found) = matches.next() {
            let (Some(func), Some(name)) = (
                capture(func_query, found, "func"),
                capture(func_query, found, "name"),
            ) else {
                continue;
            };
            let start_line = func.start_position().row + 1;
            let end_line = func.end_position().row + 1;
            functions.push(FunctionInfo {
                driver: driver.to_owned(),
                file: file.to_owned(),
                name: node_text(name, source),
                start_line,
                end_line,
                line_count: end_line - start_line + 1,
                // Cyclomatic complexity: 1 (base path) + branch nodes.
                complexity: 1 + self.count(branch_query, func, source),
            });
        }
        functions
    }

    fn count(&self, query: &Query, node: Node, source: &[u8]) -> usize {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(query, node, source);
        let mut total = 0;
        while matches.next().is_some() {
            total += 1;
        }
        total
    }

    /// Classify an unsafe block/fn by purpose (v1 classify_unsafe).
    fn classify_unsafe(&self, node: Node, source: &[u8]) -> &'static str {
        let text = node_text(node, source);
        let lower = text.to_lowercase();
        if text.contains("bindings::") || text.contains("extern \"C\"") || lower.contains("c_void")
        {
            return "ffi";
        }
        if text.contains("asm!") || text.contains("global_asm!") || text.contains("core::arch") {
            return "asm";
        }
        if lower.contains("transmute") {
            return "transmute";
        }
        if lower.contains("static mut") {
            return "static_mut";
        }
        if ["get_unchecked", "unreachable_unchecked", "assume("]
            .iter()
            .any(|keyword| lower.contains(keyword))
        {
            return "perf";
        }
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&self.rs_call, node, source);
        while let Some(found) = matches.next() {
            let Some(callee) = found.captures().first().map(|capture| capture.node) else {
                continue;
            };
            let callee = node_text(callee, source);
            if ["as_ptr", "from_raw", "into_raw", ".write", ".read"]
                .iter()
                .any(|keyword| callee.contains(keyword))
            {
                return "ptr_deref";
            }
        }
        if text.contains("as *const") || text.contains("as *mut") || text.contains(".offset(") {
            return "ptr_deref";
        }
        "other"
    }

    /// tokei-style per-line classification from the AST: a line with
    /// any non-comment token is code; otherwise comment if its
    /// content sits inside comment nodes; otherwise blank.
    fn loc(
        &self,
        comment_query: &Query,
        root: Node,
        source: &[u8],
        driver: &str,
        file: &str,
        language: &'static str,
    ) -> Loc {
        let mut comment_ranges: Vec<(usize, usize)> = Vec::new();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(comment_query, root, source);
        while let Some(found) = matches.next() {
            if let Some(node) = found.captures().first().map(|capture| capture.node) {
                comment_ranges.push((node.start_byte(), node.end_byte()));
            }
        }
        let in_comment = |offset: usize| {
            comment_ranges
                .iter()
                .any(|&(lo, hi)| offset >= lo && offset < hi)
        };

        let (mut blank, mut comment, mut code) = (0, 0, 0);
        let mut offset = 0;
        for line in source.split_inclusive(|&byte| byte == b'\n') {
            let content: Vec<usize> = line
                .iter()
                .enumerate()
                .filter(|(_, byte)| !byte.is_ascii_whitespace())
                .map(|(at, _)| offset + at)
                .collect();
            if content.is_empty() {
                blank += 1;
            } else if content.iter().all(|&at| in_comment(at)) {
                comment += 1;
            } else {
                code += 1;
            }
            offset += line.len();
        }
        Loc {
            driver: driver.to_owned(),
            file: file.to_owned(),
            language,
            blank,
            comment,
            code,
        }
    }
}

fn parse(language: &Language, source: &[u8], path: &Path) -> Result<tree_sitter::Tree, Error> {
    let mut parser = Parser::new();
    parser
        .set_language(language)
        .map_err(|err| Error::Query(err.to_string()))?;
    parser
        .parse(source, None)
        .ok_or_else(|| Error::Parse(path.display().to_string()))
}

fn capture<'t>(
    query: &Query,
    found: &tree_sitter::QueryMatch<'_, 't>,
    name: &str,
) -> Option<Node<'t>> {
    let index = query.capture_index_for_name(name)?;
    found
        .captures()
        .iter()
        .find(|capture| capture.index == index)
        .map(|capture| capture.node)
}

fn node_text(node: Node, source: &[u8]) -> String {
    String::from_utf8_lossy(&source[node.start_byte()..node.end_byte()]).into_owned()
}

fn preview(text: &str) -> String {
    let line = text.replace('\n', " ");
    let line = line.trim();
    if line.len() > 120 {
        format!("{}...", &line[..120])
    } else {
        line.to_owned()
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

#[derive(Debug)]
pub enum Error {
    Io(String, std::io::Error),
    Query(String),
    Parse(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(path, err) => write!(f, "reading {path}: {err}"),
            Error::Query(err) => write!(f, "tree-sitter query: {err}"),
            Error::Parse(path) => write!(f, "tree-sitter could not parse {path}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(name: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("koxi-ast-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn c_metrics_match_the_fixture() {
        let path = write_tmp(
            "fixture.c",
            r#"/* header comment
   spanning two lines */
static int touch(struct thing *t, int n)
{
	char buf[8];
	void *p = kmalloc(n, GFP_KERNEL);
	if (!p)
		return -1;
	memcpy(buf, t->data, n);
	*t->cursor = (int)n;
	kfree(p);
	return n > 0 ? 1 : 0;
}
"#,
        );
        let analyzer = Analyzer::new().unwrap();
        let mut results = Results::default();
        analyzer
            .analyze_c_file(&path, "null_blk", &mut results)
            .unwrap();

        assert_eq!(results.functions.len(), 1);
        let func = &results.functions[0];
        assert_eq!(func.name, "touch");
        // 1 + if + conditional_expression
        assert_eq!(func.complexity, 3);

        let density = &results.densities[0];
        assert_eq!(density.total_functions, 1);
        assert_eq!(density.alloc_calls, 1);
        assert_eq!(density.free_calls, 1);
        assert_eq!(density.memop_calls, 1);
        assert_eq!(density.cast_exprs, 1);
        // *t->cursor (deref) + t->data and t->cursor (arrows)
        assert_eq!(density.ptr_derefs, 3);

        let loc = &results.loc[0];
        assert_eq!(loc.comment, 2, "block comment spans two lines");
        assert_eq!(loc.blank, 0);
        assert!(loc.code >= 10);
    }

    #[test]
    fn rust_unsafe_sites_are_found_and_classified() {
        let path = write_tmp(
            "fixture.rs",
            r#"// driver body
fn safe_one(x: u32) -> u32 {
    if x > 0 { x } else { 0 }
}

fn calls_ffi() {
    unsafe { bindings::queue_flag_set(1) };
}

unsafe fn raw_read(p: *const u8) -> u8 {
    *p
}

struct Wrapper(u32);
unsafe impl Send for Wrapper {}
"#,
        );
        let analyzer = Analyzer::new().unwrap();
        let mut results = Results::default();
        analyzer
            .analyze_rs_file(&path, "rnull", "driver", &mut results)
            .unwrap();

        assert_eq!(results.functions.len(), 3);
        let density = &results.densities[0];
        assert_eq!(density.unsafe_blocks, 1);
        assert_eq!(density.unsafe_fns, 1);
        assert_eq!(density.unsafe_impls, 1, "unsafe impl Send is surface too");

        let block = results
            .sites
            .iter()
            .find(|site| site.node_type == "unsafe_block")
            .unwrap();
        assert_eq!(block.purpose, "ffi");
        assert_eq!(block.source, "driver");
        let func = results
            .sites
            .iter()
            .find(|site| site.node_type == "unsafe_fn")
            .unwrap();
        assert!(func.preview.contains("raw_read"));

        let loc = &results.loc[0];
        assert_eq!(loc.comment, 1);
        assert_eq!(loc.blank, 3);
    }
}
