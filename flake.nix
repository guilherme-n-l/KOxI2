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
    flake-utils.lib.eachSystem
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
            };
          };

          koxi = pkgs.rustPlatform.buildRustPackage {
            pname = "koxi";
            version = "0.1.0";
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
            inherit koxi;
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
          };

          # nixfmt-tree = treefmt wrapper; bare nixfmt reads stdin under
          # `nix fmt` instead of walking the tree.
          formatter = pkgs.nixfmt-tree;
        }
      );
}
