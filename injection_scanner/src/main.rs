use clap::Parser;
use std::fs;

mod engine;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: Option<String>,

    #[arg(short, long)]
    file: Option<String>,

    #[arg(short, long)]
    output: Option<String>,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    let scanner = engine::Engine::new();

    let text_to_scan = if let Some(input) = args.input {
        input
    } else if let Some(file_path) = args.file {
        fs::read_to_string(&file_path).unwrap_or_else(|_| {
            eprintln!("Error reading file: {}", file_path);
            std::process::exit(1);
        })
    } else {
        eprintln!("Error: Must provide either --input or --file");
        std::process::exit(1);
    };

    let result = scanner.scan(&text_to_scan);

    if let Some(format) = args.output {
        if format == "json" {
            match serde_json::to_string(&result) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error serializing JSON: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("Unknown output format: {}", format);
        }
    } else {
        println!(
            "Scan Result: {} (Risk Score: {}/100, Level: {})",
            if result.is_safe { "SAFE" } else { "THREAT DETECTED" },
            result.risk_score,
            result.threat_level
        );
        if args.verbose && !result.matches.is_empty() {
            println!("Matches:");
            for (cat, conf, snip) in result.matches {
                println!("  - [{}] (conf: {:.2}) -> {}", cat, conf, snip);
            }
        }
    }
}
