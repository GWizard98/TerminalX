use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use std::io::{self, Write};
use std::time::Duration;

pub async fn run_repl() -> Result<()> {
    println!("🔸 Cyber-Guardian Interactive REPL (type 'help' for commands, 'exit' to quit)");

    let theme = ColorfulTheme::default();

    loop {
        // Prompt for command
        let cmd: String = Input::with_theme(&theme)
            .with_prompt("cg>")
            .allow_empty(false)
            .interact_text()?;

        let cmd = cmd.trim();
        match cmd {
            "help" => {
                println!("Commands:\n  help                - Show this help\n  status              - Show system status\n  check | selfcheck   - Run a quick self-check\n  refresh             - Reprint status summary\n  tail                - Follow recent logs\n  serve               - Start API server on :3000\n  clear               - Clear screen\n  exit | quit         - Leave REPL");
            }
            "status" => {
                let snap = crate::health::quick_self_check();
                println!("📊 {}", snap.format_summary());
                if let Some(line) = crate::health::read_self_awareness_summary::<&str>(None) {
                    println!("🧠 Self-awareness: {}", line);
                }
                // Show license summary
                let mut lm = crate::license::LicenseManager::new();
                if lm.initialize().is_ok() {
                    if let Some(info) = lm.get_license_info() {
                        println!("🔐 License: {} ({})", info.tier, info.email);
                    }
                }
            }
            "check" | "selfcheck" => {
                println!("⏳ Running quick self-check...");
                let snap = crate::health::quick_self_check();
                tokio::time::sleep(Duration::from_millis(300)).await;
                println!("✅ {}", snap.format_summary());
                // Try to trigger local Cyber-Guard binary self-assessment
                match crate::health::trigger_local_self_check() {
                    Ok(output) => {
                        let trimmed = output.lines().take(10).collect::<Vec<_>>().join("\n");
                        println!("🔧 Local CG output (first lines):\n{}", trimmed);
                    }
                    Err(e) => println!("⚠️  Could not trigger local CG: {}", e),
                }
                if let Some(line) = crate::health::read_self_awareness_summary::<&str>(None) {
                    println!("🧠 Self-awareness: {}", line);
                }
            }
            "refresh" => {
                let snap = crate::health::quick_self_check();
                println!("🔄 {}", snap.format_summary());
            }
            "tail" => {
                println!("📜 Tailing logs (Ctrl+C to stop)...");
                // Simple demo tail: print a few lines with delay
                for i in 1..=5u8 {
                    println!("[log] heartbeat {i}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                println!("(tail ended)");
            }
            "serve" => {
                println!("🚀 Launch `cyber_guardian serve --port 3000` in another terminal to run the API");
            }
            "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                io::stdout().flush().ok();
            }
            "exit" | "quit" => {
                println!("Bye.");
                break;
            }
            other if other.starts_with("help ") => {
                println!("No topic help yet.");
            }
            _ => {
                // Optional quick actions menu
                let items = vec!["help", "status", "check", "tail", "serve", "exit"];
                let selection = Select::with_theme(&theme)
                    .with_prompt("Unknown command. Did you mean:")
                    .default(0)
                    .items(&items)
                    .interact_opt()?;
                if let Some(idx) = selection {
                    println!("→ {}", items[idx]);
                }
            }
        }
    }

    Ok(())
}
