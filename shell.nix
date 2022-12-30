{ 
	pkgs ? import <nixpkgs> {},
}:
with pkgs;
mkShell {
	buildInputs = [
		rustChannels.nightly.rust
	];
	shellHook = ''
		export RUST_SRC_PATH="${rustChannels.nightly.rust-src}/lib/rustlib/src/rust/library"
	'';
}
