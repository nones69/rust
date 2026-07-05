pub enum Command {
    Open(String),
    Read,
    Write(String),
    AiAssist(String),
    Quit,
}

pub fn parse(input: &str) -> Option<Command> {
    let trimmed = input.trim();

    if trimmed == "quit" {
        return Some(Command::Quit);
    }
    if trimmed == "read" {
        return Some(Command::Read);
    }

    if let Some(rest) = trimmed.strip_prefix("open ") {
        return Some(Command::Open(rest.to_string()));
    }

    if let Some(rest) = trimmed.strip_prefix("write ") {
        return Some(Command::Write(rest.to_string()));
    }

    if let Some(rest) = trimmed.strip_prefix("ai ") {
        return Some(Command::AiAssist(rest.to_string()));
    }

    None
}
