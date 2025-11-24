use mdbook_preprocessor::book::{Book, BookItem};
use mdbook_preprocessor::errors::Result;
use mdbook_preprocessor::{Preprocessor, PreprocessorContext};
use std::io;
use std::process;

/// Preprocessor that injects {{version}} and {{version_minor}} from Cargo.toml
pub struct ProjectVersionPreprocessor;

impl ProjectVersionPreprocessor {
    pub fn new() -> Self {
        ProjectVersionPreprocessor
    }

    /// Read version from project's Cargo.toml
    fn get_version() -> Result<(String, String)> {
        // Try different paths relative to where mdbook is run
        let paths = [
            "../Cargo.toml",           // From book/ directory
            "../../Cargo.toml",        // From book/mdbook-project-version/
            "Cargo.toml",              // From project root
        ];

        let cargo_toml = paths
            .iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
            .ok_or_else(|| anyhow::anyhow!("Could not find Cargo.toml in parent directories"))?;

        let parsed: toml::Value = toml::from_str(&cargo_toml)
            .map_err(|e| anyhow::anyhow!("Failed to parse Cargo.toml: {}", e))?;

        let version = parsed
            .get("package")
            .and_then(|p| p.get("version"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("No package.version found in Cargo.toml"))?
            .to_string();

        // Extract minor version: "0.5.2" -> "0.5"
        let version_minor = version
            .split('.')
            .take(2)
            .collect::<Vec<_>>()
            .join(".");

        Ok((version, version_minor))
    }
}

impl Preprocessor for ProjectVersionPreprocessor {
    fn name(&self) -> &str {
        "project-version"
    }

    fn run(&self, _ctx: &PreprocessorContext, mut book: Book) -> Result<Book> {
        let (version, version_minor) = Self::get_version()?;

        eprintln!(
            "[mdbook-project-version] Replacing {{{{version}}}} with {} and {{{{version_minor}}}} with {}",
            version, version_minor
        );

        // Walk through all chapters and replace placeholders
        book.for_each_mut(|item| {
            if let BookItem::Chapter(chapter) = item {
                chapter.content = chapter
                    .content
                    .replace("{{version}}", &version)
                    .replace("{{version_minor}}", &version_minor);
            }
        });

        Ok(book)
    }

    fn supports_renderer(&self, _renderer: &str) -> Result<bool> {
        Ok(true)
    }
}

fn main() {
    let preprocessor = ProjectVersionPreprocessor::new();

    // Handle "supports" command
    if std::env::args().nth(1).as_deref() == Some("supports") {
        process::exit(0);
    }

    if let Err(e) = handle_preprocessing(&preprocessor) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn handle_preprocessing(pre: &dyn Preprocessor) -> Result<()> {
    let (ctx, book) = mdbook_preprocessor::parse_input(io::stdin())?;

    let processed_book = pre.run(&ctx, book)?;
    serde_json::to_writer(io::stdout(), &processed_book)?;

    Ok(())
}
