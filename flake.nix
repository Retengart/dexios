{
  inputs = {
    # Pinned to a stable release channel instead of nixpkgs-unstable so the
    # build is reproducible against a curated, security-supported channel.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    utils.url = "github:numtide/flake-utils";

    # The workspace is edition 2024 / resolver 3 with an MSRV of 1.88, but the
    # nixos-25.05 channel ships rustc 1.86. rust-overlay lets us pin an exact
    # toolchain (>= MSRV) for both the package build and the dev shell.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, utils, rust-overlay }:
    let
      inherit (builtins) fromTOML readFile;
      dexiosCargoToml = fromTOML (readFile ./dexios/Cargo.toml);
      workspaceCargoToml = fromTOML (readFile ./Cargo.toml);

      # MSRV declared in the workspace manifest (e.g. "1.88"). The toolchain
      # selected below must be >= this, otherwise edition 2024 / resolver 3
      # will not build.
      msrv = workspaceCargoToml.workspace.package.rust-version;

      # rust-overlay keys stable toolchains by the full "major.minor.patch"
      # version, so normalise a two-component MSRV (e.g. "1.88") to "1.88.0".
      rustVersion =
        let parts = builtins.splitVersion msrv;
        in if builtins.length parts < 3 then "${msrv}.0" else msrv;

      # rustPlatform built around the pinned toolchain so buildRustPackage uses
      # the same rustc/cargo as the dev shell.
      mkRustPlatform = pkgs:
        let
          rustToolchain = pkgs.rust-bin.stable.${rustVersion}.default;
        in
        {
          toolchain = rustToolchain;
          platform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
        };

      mkDexios = { lib, rustPlatform, ... }: rustPlatform.buildRustPackage {
        inherit (dexiosCargoToml.package) name version;

        src = lib.cleanSource ./.;

        doCheck = true;

        cargoLock.lockFile = ./Cargo.lock;
      };
    in
    {
      overlays = rec {
        dexios = final: prev: {
          dexios = prev.callPackage mkDexios {
            rustPlatform = (mkRustPlatform final).platform;
          };
        };
        default = dexios;
      };
    }
    //
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        rust = mkRustPlatform pkgs;
        dexios = pkgs.callPackage mkDexios {
          rustPlatform = rust.platform;
        };
      in
      {
        # Executes by `nix build .#<name>`
        packages = {
          inherit dexios;
          default = dexios;
        };
        # the same but deprecated in Nix 2.7
        defaultPackage = self.packages.${system}.default;

        # Executes by `nix run .#<name> -- <args?>`
        apps = {
          dexios = {
            type = "app";
            program = "${dexios}/bin/dexios";
          };
          default = self.apps.${system}.dexios;
        };
        # Executes by `nix run . -- <args?>`
        # the same but deprecated in Nix 2.7
        defaultApp = self.apps.${system}.default;

        # Used by `nix develop`
        devShell = pkgs.mkShell {
          # The pinned toolchain (>= MSRV) bundles cargo/rustc/clippy/rustfmt.
          packages = [ rust.toolchain pkgs.rust-analyzer ];
          RUST_SRC_PATH = "${rust.toolchain}/lib/rustlib/src/rust/library";
        };
      });
}
