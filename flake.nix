{
  description = "KOxI v2 - Kernel Oxidation Instrument, Rust rewrite";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    # Kernel-era rust toolchain: kernel 6.19 fails to compile under
    # rustc >= 1.9x from unstable (custom-target gating, E0310), while
    # 25.11's 1.91 is contemporary with the kernel and builds it clean.
    nixpkgs-kernel-rust.url = "github:nixos/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-kernel-rust,
      flake-utils,
      git-hooks,
      ...
    }:
    # Not eachDefaultSystem: that list still contains x86_64-darwin,
    # which nixpkgs 26.11 (current unstable) dropped and hard-errors on.
    (flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ]
      (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          krustPkgs = import nixpkgs-kernel-rust { inherit system; };
          inherit (pkgs) lib;

          # Tools that run on the build machine while compiling koxi itself
          # (buildPlatform under cross-compilation).
          nativeBuildInputs = with pkgs; [
            rustc
            cargo
            pkg-config
          ];

          # Libraries linked into the koxi binary (hostPlatform under cross).
          # openssl covers the usual -sys crates (openssl-sys, libgit2);
          # adjust as Cargo dependencies land.
          buildInputs = with pkgs; [
            openssl
          ];

          # Runtime tool environment: everything the harness shells out to,
          # mirroring block/dependencies.md from KOxI v1. Not build
          # dependencies of the crate.
          extraPackages =
            # Kernel / BusyBox / dropbear / fio build chain. Linux-only:
            # kernels are built natively, never from a darwin host.
            lib.optionals pkgs.stdenv.hostPlatform.isLinux (
              with pkgs;
              [
                gcc
                gnumake
                patch
                autoconf
                automake
                libtool
                bc
                flex
                bison
                perl
                elfutils # libelf
                openssl # certs, module signing host tools
                pahole
                ncurses # menuconfig
                kmod # modpost, depmod
                util-linux # setsid
                # Rust-for-Linux (rnull): without rustc/bindgen on
                # PATH, Kconfig silently disables CONFIG_RUST. Pinned
                # to the kernel-era toolchain (see the input comment);
                # rustfmt quiets bindgen's post-processing.
                krustPkgs.rustc
                krustPkgs.rust-bindgen
                krustPkgs.rustfmt
                # The LLVM chain for [build].toolchain = "llvm", which
                # builds the kernel with kbuild's LLVM=1: clang plus
                # ld.lld and the llvm-* binutils, since LLVM=1 swaps
                # all of them together. Deliberately from krustPkgs,
                # the same set that provides rust-bindgen above:
                # bindgen resolves libclang, and the kernel's
                # rust_is_available.sh checks that libclang against the
                # C compiler. Pulling clang from a different set risks
                # a version skew that silently drops CONFIG_RUST --
                # which the build's required-config assertion now
                # catches, but a matched pair avoids entirely.
                krustPkgs.clang
                krustPkgs.lld
                krustPkgs.llvm
                # bfd.h, for objtool. Its Makefile decides whether to
                # build the disassembler by *linking* a probe against
                # -lopcodes -lbfd -liberty, declaring the symbol itself
                # rather than including a header. Under clang that probe
                # links, so -DDISAS goes on and the build then includes
                # <bfd.h> -- which nixpkgs keeps in a separate dev
                # output, so it is absent and objtool fails. (Under gcc
                # the probe does not link, DISAS stays off, and the
                # mismatch never shows.) Giving it the headers makes the
                # build agree with the probe.
                libbfd.dev
              ]
            )
            # Archive / download
            ++ (with pkgs; [
              wget
              gzip
              xz
              bzip2
              cpio
              unzip
            ])
            # VM + SSH
            ++ (with pkgs; [
              qemu # qemu-system-x86_64
              openssh
            ])
            # Fuzzing, static analysis, utilities
            ++ (with pkgs; [
              go # syzkaller build
              cloc
              jq
              git
            ]);

          # musl must NOT be in any shell's packages: its lib dir would
          # enter NIX_LDFLAGS and gcc then links glibc-hosted binaries
          # against musl's libc.so, which segfault at startup. The
          # busybox build reaches musl-gcc by absolute path instead.
          # RUST_LIB_SRC: the kernel's rust_is_available.sh needs the
          # standard library sources (nixpkgs rustc does not bundle
          # rust-src).
          runtimeEnv = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            MUSL_GCC = "${pkgs.musl.dev}/bin/musl-gcc";
            RUST_LIB_SRC = "${krustPkgs.rustPlatform.rustLibSrc}";
            # Path only, deliberately NOT a shell package: static libc
            # lib dirs on NIX_LDFLAGS half-staticize every host tool
            # (fixdep died of a circular IFUNC this way). The syzkaller
            # build scopes it so the executor's -static probe passes.
            GLIBC_STATIC_LIB = "${pkgs.glibc.static}/lib";
            # The kernel's target compiler for [build].toolchain =
            # "llvm". It must be the *unwrapped* clang: the wrapper
            # injects -nostdlibinc, clang calls that unused on the
            # compilations that ignore it, and the kernel's -Werror
            # makes it fatal. Most of the tree can be quieted with
            # kbuild's user-append variables, but arch/x86/realmode and
            # drivers/firmware/efi/libstub rebuild KBUILD_CFLAGS from
            # scratch, so nothing reaches them. Target compiles need no
            # libc anyway (-nostdinc); HOSTCC is left alone, because
            # host tools do want the wrapper, and LLVM=1 takes that
            # from PATH.
            KOXI_LLVM_CC = "${krustPkgs.llvmPackages.clang-unwrapped}/bin/clang";
            # Host tools that link against openssl -- certs/extract-cert is
            # the one that bites -- record no RPATH under LLVM=1, because
            # kbuild links them with clang -fuse-ld=lld and that bypasses
            # the nix ld wrapper which would otherwise add one. They link
            # clean and then die at runtime with "libcrypto.so.3: cannot
            # open shared object file". Harmless under the GNU chain,
            # where the wrapper already records it.
            HOSTLDFLAGS = "-Wl,-rpath,${pkgs.openssl.out}/lib";
          };

          # Dev-only helpers; never needed to build or run koxi.
          devPackages = with pkgs; [
            rust-analyzer
            clippy
            rustfmt
            shellcheck
            shfmt
            nixfmt
            # LSP servers enabled in .nvim.lua (rust-analyzer above)
            nixd
            bash-language-server
            taplo
          ];

          # Source-based coverage. rustc writes .profraw with
          # `-C instrument-coverage`, and that format is version-tagged:
          # only an llvm-profdata from the SAME LLVM as rustc can read
          # it. rustc 1.97 is LLVM 21, so pin llvmPackages_21 rather
          # than llvmPackages_latest, which drifts ahead of the
          # toolchain and fails with "unsupported profile version".
          coverageLlvm = pkgs.llvmPackages_21.llvm;

          # Git pre-commit hooks; also run repo-wide by `nix flake check`.
          pre-commit = git-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              rustfmt.enable = true;
              clippy.enable = true;
              nixfmt-rfc-style = {
                enable = true;
                # Avoids the deprecated nixfmt-rfc-style alias the hook
                # defaults to.
                package = pkgs.nixfmt;
              };
              shellcheck.enable = true;
              shfmt.enable = true;
              prettier-md = {
                enable = true;
                name = "prettier (markdown, json)";
                entry = "${lib.getExe pkgs.prettier} --write";
                files = "\\.(md|json)$";
              };
            };
          };

          # Oracle fixture generation for src/stats.rs: lint the
          # generator scripts, then regenerate the golden JSONs from
          # THIS flake's nixpkgs, so the pinned scipy/R versions come
          # from flake.lock and never from a machine channel. The
          # closure (python+scipy, R+pROC, linters) is realized only
          # when the app runs — deliberately not part of any dev
          # shell. Usage: nix run .#gen-stats-fixtures
          gen-stats-fixtures = pkgs.writeShellApplication {
            name = "gen-stats-fixtures";
            runtimeInputs = [
              pkgs.ruff
              pkgs.basedpyright
              pkgs.prettier
              pkgs.git
              (pkgs.python3.withPackages (p: [
                p.scipy
                p.numpy
              ]))
              (pkgs.rWrapper.override {
                packages = with pkgs.rPackages; [
                  pROC
                  jsonlite
                  lintr
                ];
              })
            ];
            text = ''
              cd "$(git rev-parse --show-toplevel)"
              ruff format tests/oracle/gen_stats_scipy.py
              ruff check tests/oracle/gen_stats_scipy.py
              basedpyright --pythonpath "$(command -v python3)" --project tests/oracle \
                tests/oracle/gen_stats_scipy.py
              Rscript -e 'lints <- lintr::lint("tests/oracle/gen_stats_r.R")
                          print(lints)
                          quit(status = as.integer(length(lints) > 0))'
              python3 tests/oracle/gen_stats_scipy.py > tests/fixtures/stats_scipy.json
              Rscript tests/oracle/gen_stats_r.R > tests/fixtures/stats_r.json
              # Same formatting the pre-commit prettier hook enforces,
              # so regeneration never fights it.
              prettier --log-level warn --write tests/fixtures/stats_scipy.json \
                tests/fixtures/stats_r.json
              echo "stats fixtures regenerated under the flake-locked interpreters" >&2
            '';
          };

          koxi = pkgs.rustPlatform.buildRustPackage {
            pname = "koxi";
            version = "2.0.0-rc.1";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            inherit nativeBuildInputs buildInputs;
            meta = {
              description = "Kernel Oxidation Instrument - Rust rewrite";
              mainProgram = "koxi";
            };
          };
        in
        {
          packages = {
            inherit koxi gen-stats-fixtures;
            default = koxi;
          };

          checks = {
            inherit pre-commit;
          };

          devShells = {
            default = pkgs.mkShell {
              inherit nativeBuildInputs buildInputs;
              packages = extraPackages ++ devPackages ++ pre-commit.enabledPackages;

              # Installs the git hooks on shell entry.
              shellHook = pre-commit.shellHook;

              # rust-src: used by rust-analyzer and by the kernel's Rust
              # (rnull) build, which needs the standard library sources.
              env = {
                RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
              }
              // runtimeEnv;
            };

            # Runtime environment for the harness itself: the koxi
            # binary plus everything it shells out to in order to
            # build and run the pipeline (kernel/userland toolchains,
            # qemu, syzkaller build deps). Not for developing koxi —
            # no rust toolchain, no hooks.
            koxi = pkgs.mkShell {
              packages = extraPackages ++ [ koxi ];
              env = runtimeEnv;
            };

            # Coverage runs. Carries the full runtime toolchain, not
            # just the crate's, because the numbers that matter come
            # from driving the real pipeline (kernel build, qemu, fio)
            # under an instrumented binary -- unit tests alone never
            # reach the code that shells out. Usage:
            #   nix develop .#coverage --command cargo llvm-cov --html
            coverage = pkgs.mkShell {
              inherit nativeBuildInputs buildInputs;
              packages = extraPackages ++ [
                pkgs.cargo-llvm-cov
                coverageLlvm
              ];
              env = {
                LLVM_COV = "${coverageLlvm}/bin/llvm-cov";
                LLVM_PROFDATA = "${coverageLlvm}/bin/llvm-profdata";
              }
              // runtimeEnv;
            };
          };

          # nixfmt-tree = treefmt wrapper; bare nixfmt reads stdin under
          # `nix fmt` instead of walking the tree.
          formatter = pkgs.nixfmt-tree;
        }
      )
    )
    // {
      # Project starter for koxi *users* (a dir with a koxi.toml, not
      # this repo): `nix flake init -t github:guilherme-n-l/KOxI2#koxi`
      # or, offline, `koxi nix init`.
      templates = rec {
        koxi = {
          path = ./templates/koxi;
          description = "KOxI project runtime environment (koxi + pipeline toolchain)";
          welcomeText = "Run `nix develop`, then `koxi block test` and `koxi block setup`.";
        };
        default = koxi;
      };
    };
}
