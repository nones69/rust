mod commands;
mod editor;
mod token_request;

use commands::{parse, Command};
use editor::Editor;
use std::io::{self, Write};
use token_request::request_notes_token;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = request_notes_token();
    let mut ed = Editor::new("/tmp/intentos.sock", token);

    println!("Governed Notes — IntentKernel application");
    println!("Commands:");
    println!("  open <filename>");
    println!("  read");
    println!("  write <text>");
    println!("  ai <prompt>");
    println!("  quit");
    println!();

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut line = String::new();
        io::stdin().read_line(&mut line)?;

        match parse(&line) {
            Some(Command::Open(path)) => {
                if let Err(e) = ed.open(&path) {
                    eprintln!("Error: {e}");
                }
            }
            Some(Command::Read) => {
                if let Err(e) = ed.read() {
                    eprintln!("Error: {e}");
                }
            }
            Some(Command::Write(text)) => {
                if let Err(e) = ed.write(&text) {
                    eprintln!("Error: {e}");
                }
            }
            Some(Command::AiAssist(prompt)) => {
                if let Err(e) = ed.ai_assist(&prompt) {
                    eprintln!("Error: {e}");
                }
            }
            Some(Command::Quit) => {
                println!("Goodbye.");
                break;
            }
            None => {
                if !line.trim().is_empty() {
                    println!(
                        "Unknown command. Try: open <file>, read, write <text>, ai <prompt>, quit"
                    );
                }
            }
        }
    }

    Ok(())
}
