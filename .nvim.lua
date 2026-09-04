local vim = vim
vim.lsp.enable({
	"rust_analyzer",
	"nixd", -- Nix
	"bashls", -- shell scripts
	"taplo", -- Cargo.toml
})
