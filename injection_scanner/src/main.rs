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
    let engine = engine::Engine::new();

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

    let result = engine.scan(&text_to_scan);

    if let Some(format) = args.output {
        if format == "json" {
            let json = serde_json::to_string(&result).unwrap();
            println!("{}", json);
        } else {
            eprintln!("Unknown output format: {}", format);
        }
    } else {
        println!("Scan Result: {}", if result.is_safe { "SAFE" } else { "THREAT DETECTED" });
        if args.verbose && !result.is_safe {
            println!("Threat Level: {}", result.threat_level);
            println!("Matches:");
            for (cat, conf, snip) in result.matches {
                println!("  - [{}] (conf: {}) -> {}", cat, conf, snip);
            }
        }
    }
}
