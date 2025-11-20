use std::env;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

fn main() {
    generate_psl_phf();
    generate_c_header();
}

/// Generate perfect hash set for Public Suffix List at build time
fn generate_psl_phf() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = PathBuf::from(&out_dir).join("psl_phf.rs");
    
    // Read PSL data
    let psl_data = fs::read_to_string("src/data/public_suffix_list.dat")
        .expect("Failed to read PSL data");
    
    // Parse PSL entries (skip comments and empty lines)
    let entries: Vec<&str> = psl_data
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect();
    
    println!("cargo:warning=Generating PHF for {} PSL entries", entries.len());
    
    // Generate static byte arrays for each PSL entry (supports UTF-8)
    let mut file = BufWriter::new(fs::File::create(&dest_path).expect("Failed to create PHF file"));
    
    writeln!(&mut file, "// Generated at build time from public_suffix_list.dat").unwrap();
    writeln!(&mut file, "// Contains {} PSL entries", entries.len()).unwrap();
    writeln!(&mut file).unwrap();
    
    // Generate static byte arrays for each entry
    for (idx, entry) in entries.iter().enumerate() {
        writeln!(
            &mut file,
            "static ENTRY_{}: &[u8] = &{:?};",
            idx,
            entry.as_bytes()
        ).unwrap();
    }
    
    writeln!(&mut file).unwrap();
    
    // Build PHF Set using byte slice keys with phf_codegen
    // We'll build with the actual byte content, then the PHF will work directly
    writeln!(&mut file, "/// PHF set of PSL entries as byte slices").unwrap();
    writeln!(&mut file, "#[allow(clippy::all)]").unwrap();
    writeln!(&mut file, "static PSL_SUFFIXES: phf::Set<&'static [u8]> = ").unwrap();
    
    // Use phf_codegen::Set with the actual entry strings
    // phf_codegen works with &str, and we'll convert at compile time
    let mut set_builder = phf_codegen::Set::new();
    for entry in &entries {
        set_builder.entry(entry);
    }
    
    // Generate the PHF code
    let phf_code = set_builder.build().to_string();
    
    // Post-process: replace all string literals with ENTRY_X references
    // For UTF-8 entries, Rust escapes them with \u{...}, so we need to handle both
    let mut fixed_code = phf_code;
    for (idx, entry) in entries.iter().enumerate() {
        // Try direct replacement first
        let pattern = format!("\"{}\"", entry);
        if fixed_code.contains(&pattern) {
            fixed_code = fixed_code.replace(&pattern, &format!("ENTRY_{}", idx));
        } else {
            // UTF-8 entry was escaped - try escaped version
            // Rust Debug format escapes non-ASCII, so use that
            let escaped = format!("{:?}", entry);
            if fixed_code.contains(&escaped) {
                fixed_code = fixed_code.replace(&escaped, &format!("ENTRY_{}", idx));
            } else {
                eprintln!("Warning: Could not find entry {} in PHF code", idx);
            }
        }
    }
    
    write!(&mut file, "{}", fixed_code).unwrap();
    writeln!(&mut file, ";").unwrap();
    
    // Tell cargo to rerun if PSL changes
    println!("cargo:rerun-if-changed=src/data/public_suffix_list.dat");
}

fn generate_c_header() {
    // Skip header generation on docs.rs - the source directory is read-only
    // The C API documentation doesn't need the generated header
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=Skipping cbindgen on docs.rs (read-only filesystem)");
        return;
    }

    // Get crate directory
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // Ensure include directory exists
    let include_dir = PathBuf::from(&crate_dir).join("include").join("matchy");
    std::fs::create_dir_all(&include_dir).expect("Failed to create include directory");

    // Generate C header with cbindgen
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("Unable to find cbindgen.toml configuration file");

    let header_path = include_dir.join("matchy.h");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(&header_path);

    // Post-process: fix sockaddr references (cbindgen doesn't handle libc::sockaddr properly)
    let header_content =
        std::fs::read_to_string(&header_path).expect("Failed to read generated header");
    let fixed_header = header_content.replace(
        "const sockaddr *sockaddr",
        "const struct sockaddr *sockaddr",
    );
    std::fs::write(&header_path, fixed_header).expect("Failed to write fixed header");

    // Tell cargo to rerun if these change
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
