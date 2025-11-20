use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;

const PSL_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";
const OUTPUT_PATH: &str = "../../src/data/public_suffix_list.dat";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Downloading Public Suffix List from {}...", PSL_URL);
    
    // Download PSL
    let response = ureq::get(PSL_URL).call()?;
    let psl_content = response.into_string()?;
    
    println!("Processing entries and generating punycode versions...");
    
    // Use HashSet to deduplicate entries
    let mut all_entries = HashSet::new();
    let mut utf8_count = 0;
    let mut punycode_count = 0;
    
    for line in psl_content.lines() {
        let trimmed = line.trim();
        
        // Keep comments and empty lines as-is
        if trimmed.is_empty() || trimmed.starts_with("//") {
            all_entries.insert(line.to_string());
            continue;
        }
        
        // Add original entry
        all_entries.insert(trimmed.to_string());
        
        // Check if entry contains non-ASCII
        if trimmed.chars().any(|c| !c.is_ascii()) {
            utf8_count += 1;
            
            // Convert to punycode
            match idna::domain_to_ascii(trimmed) {
                Ok(punycode) => {
                    if punycode != trimmed {
                        all_entries.insert(punycode);
                        punycode_count += 1;
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to convert '{}' to punycode: {}", trimmed, e);
                }
            }
        }
    }
    
    println!("Found {} UTF-8 entries", utf8_count);
    println!("Generated {} punycode entries", punycode_count);
    println!("Total unique entries: {}", all_entries.len());
    
    // Sort entries for consistency
    let mut sorted_entries: Vec<_> = all_entries.into_iter().collect();
    sorted_entries.sort();
    
    // Write output file
    let output_path = Path::new(OUTPUT_PATH);
    let mut file = fs::File::create(output_path)?;
    
    for entry in sorted_entries {
        writeln!(file, "{}", entry)?;
    }
    
    println!("\n✓ Saved to {}", OUTPUT_PATH);
    println!("\nNext steps:");
    println!("  1. cargo test    # Verify everything works");
    println!("  2. git add {}", OUTPUT_PATH);
    println!("  3. git commit -m \"Update Public Suffix List with punycode\"");
    
    Ok(())
}
