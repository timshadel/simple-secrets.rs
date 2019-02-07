use std::process::Command;

fn main() {
	let orig = env!("CARGO_PKG_VERSION");
	let cmd = Command::new("git").args(&["describe", "--tags", "--long", "--dirty=-modified"]).output().unwrap();
	assert!(cmd.status.success());
	let hash = std::str::from_utf8(&cmd.stdout[..]).unwrap().trim();
	if let Some(index) = hash.find("-g") {
		let suffix = &hash[(index+2)..];
		let version = format!("{} ({})", orig, suffix);
		println!("cargo:rustc-env=CARGO_PKG_VERSION={}", version);
		println!("cargo:rerun-if-changed=(nonexistentfile)");
	}
}
