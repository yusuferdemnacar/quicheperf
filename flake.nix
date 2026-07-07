{
  description = "quicheperf flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # The custom quiche checkout that quicheperf depends on.
    #
    # `flake = false` is REQUIRED: quiche is a plain source tree, not a flake.
    # Without it Nix looks for a flake.nix inside quiche and errors with
    # "Path 'flake.nix' does not exist in Git repository ...". submodules=1 is
    # required so the vendored BoringSSL submodule comes along.
    #
    # Default is the published github repo. To build against your LOCAL sibling
    # checkout instead, override per-invocation (no file edits needed):
    #
    #   nix build --override-input quiche 'git+file:../quiche?submodules=1'
    #
    # git+file tracks your working tree (uncommitted edits to tracked files are
    # picked up) while respecting quiche's .gitignore, so the multi-GB target/ is
    # NOT copied into the store. Caveat: brand-new files in quiche must be
    # `git add`-ed to be visible (untracked files are excluded). Do NOT use
    # `path:../quiche` — that ignores .gitignore and copies target/ (~12G).
    quiche = {
      url = "git+https://github.com/hendrikcech/quiche?submodules=1&ref=frame-scheduler";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, rust-overlay, quiche }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Keep everything in the src tree
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type: true;
        };

      in
      {
        packages.default = craneLib.buildPackage {
          inherit src;
          strictDeps = true;

          # The sandbox cannot see ../quiche (it is outside this flake), so we
          # reconstruct the sibling directory from the `quiche` input and add a
          # crate-local [patch] that redirects the quiche/qlog git dependency to
          # it. Crane writes its own vendoring config to $CARGO_HOME/config.toml,
          # so this crate-local .cargo/config.toml merges rather than clobbers.
          #
          # This runs for both the deps-only and final derivations, so quiche
          # (and BoringSSL) build once and get cached in the deps layer.
          postUnpack = ''
            mkdir -p $sourceRoot/../quiche
            cp -a ${quiche}/. $sourceRoot/../quiche/
            chmod -R +w $sourceRoot/../quiche
            # Drop build artifacts / VCS metadata that a path: input may carry.
            rm -rf $sourceRoot/../quiche/target \
                   $sourceRoot/../quiche/*/target \
                   $sourceRoot/../quiche/.git

            mkdir -p $sourceRoot/.cargo
            cat > $sourceRoot/.cargo/config.toml <<'EOF'
            [patch."https://github.com/hendrikcech/quiche"]
            quiche = { path = "../quiche/quiche" }
            qlog = { path = "../quiche/qlog" }
            EOF
          '';

          buildInputs = [ ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
          ];

          nativeBuildInputs = [ pkgs.cmake pkgs.pkg-config pkgs.perl pkgs.go ];
        };
      }
    );
}
