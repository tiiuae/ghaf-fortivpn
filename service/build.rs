// SPDX-FileCopyrightText: 2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo:rerun-if-changed=src/openconnect.c");
    let library = pkg_config::Config::new()
        .cargo_metadata(false)
        .atleast_version("9.12")
        .probe("openconnect")
        .expect("OpenConnect development files are required");
    cc::Build::new()
        .file("src/openconnect.c")
        .includes(library.include_paths)
        .compile("ghaf-openconnect");
    for path in library.link_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    for library in library.libs {
        println!("cargo:rustc-link-lib={library}");
    }
}
