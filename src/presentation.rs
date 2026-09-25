use std::io::{self, IsTerminal, Write};

use anstream::{AutoStream, ColorChoice};
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ColorMode {
    /// Color interactive terminals; respect NO_COLOR and TERM=dumb.
    #[default]
    Auto,
    /// Explicitly emit color, including on ANSI-capable serial consoles.
    Always,
    /// Never emit color.
    Never,
}

impl ColorMode {
    pub fn enabled(self) -> bool {
        let term = std::env::var_os("TERM");
        self.enabled_for(
            io::stdout().is_terminal(),
            std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            term.as_ref().is_some_and(|value| value == "dumb"),
        )
    }

    fn enabled_for(self, terminal: bool, no_color: bool, dumb: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => terminal && !no_color && !dumb,
        }
    }
}

/// AutoStream handles ANSI-capable Windows terminals and legacy console output.
pub fn print(text: &str, colored: bool) -> io::Result<()> {
    let choice = if colored {
        ColorChoice::Always
    } else {
        ColorChoice::Never
    };
    let mut output = AutoStream::new(io::stdout(), choice);
    output.write_all(text.as_bytes())?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_color_respects_terminal_and_environment() {
        for terminal in [false, true] {
            for no_color in [false, true] {
                for dumb in [false, true] {
                    assert_eq!(
                        ColorMode::Auto.enabled_for(terminal, no_color, dumb),
                        terminal && !no_color && !dumb
                    );
                    assert!(ColorMode::Always.enabled_for(terminal, no_color, dumb));
                    assert!(!ColorMode::Never.enabled_for(terminal, no_color, dumb));
                }
            }
        }
    }
}
