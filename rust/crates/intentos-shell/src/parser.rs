/// Native shell command parser — tier 2 owns all user input parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLine<'a> {
    pub command: &'a str,
    pub args: Vec<&'a str>,
}

impl<'a> ParsedLine<'a> {
    pub fn parse(line: &'a str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let mut parts = line.split_whitespace().collect::<Vec<_>>();
        let command = parts.remove(0);
        Some(Self {
            command,
            args: parts,
        })
    }

    pub fn arg(&self, index: usize) -> Option<&'a str> {
        self.args.get(index).copied()
    }

    pub fn rest_from(&self, index: usize) -> String {
        self.args[index..].join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_command_and_args() {
        let p = ParsedLine::parse("flow file read").unwrap();
        assert_eq!(p.command, "flow");
        assert_eq!(p.args, vec!["file", "read"]);
    }
}