use std::{
    ffi::{OsStr, OsString},
    fmt,
    net::Ipv6Addr,
    process::{Command, ExitStatus},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTool {
    Ping,
    Trace,
    Ssh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    program: OsString,
    arguments: Vec<OsString>,
}

impl Invocation {
    pub fn for_current_platform(
        tool: NetworkTool,
        address: Ipv6Addr,
        passthrough: impl IntoIterator<Item = OsString>,
    ) -> Self {
        Self::new(tool, address, passthrough, cfg!(windows))
    }

    fn new(
        tool: NetworkTool,
        address: Ipv6Addr,
        passthrough: impl IntoIterator<Item = OsString>,
        windows: bool,
    ) -> Self {
        let (program, ipv6_flag) = match (tool, windows) {
            (NetworkTool::Ping, true) => ("ping", "-6"),
            (NetworkTool::Ping, false) => ("ping", "-6"),
            (NetworkTool::Trace, true) => ("tracert", "-6"),
            (NetworkTool::Trace, false) => ("traceroute", "-6"),
            (NetworkTool::Ssh, _) => ("ssh", "-6"),
        };

        let mut arguments = vec![OsString::from(ipv6_flag)];
        arguments.extend(passthrough);
        arguments.push(OsString::from(address.to_string()));

        Self {
            program: OsString::from(program),
            arguments,
        }
    }

    pub fn execute(&self) -> std::io::Result<ExitStatus> {
        Command::new(&self.program).args(&self.arguments).status()
    }

    pub fn program(&self) -> &OsStr {
        &self.program
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

impl fmt::Display for Invocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", display_argument(&self.program))?;
        for argument in &self.arguments {
            write!(formatter, " {}", display_argument(argument))?;
        }
        Ok(())
    }
}

fn display_argument(argument: &OsStr) -> String {
    let value = argument.to_string_lossy();
    if !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._:/%".contains(character))
    {
        value.into_owned()
    } else {
        format!("{value:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> Ipv6Addr {
        "fd7a:115c:a1e0:17::2a".parse().unwrap()
    }

    #[test]
    fn builds_windows_ping_without_a_shell() {
        let invocation = Invocation::new(
            NetworkTool::Ping,
            address(),
            [OsString::from("-n"), OsString::from("5")],
            true,
        );

        assert_eq!(invocation.program(), "ping");
        assert_eq!(
            invocation.arguments(),
            ["-6", "-n", "5", "fd7a:115c:a1e0:17::2a"].map(OsString::from)
        );
        assert_eq!(invocation.to_string(), "ping -6 -n 5 fd7a:115c:a1e0:17::2a");
    }

    #[test]
    fn chooses_the_platform_trace_executable() {
        let windows = Invocation::new(NetworkTool::Trace, address(), [], true);
        let unix = Invocation::new(NetworkTool::Trace, address(), [], false);

        assert_eq!(windows.program(), "tracert");
        assert_eq!(unix.program(), "traceroute");
    }

    #[test]
    fn quotes_display_only_without_changing_arguments() {
        let invocation = Invocation::new(
            NetworkTool::Ssh,
            address(),
            [OsString::from("-l"), OsString::from("Example User")],
            true,
        );

        assert_eq!(invocation.arguments()[2], "Example User");
        assert!(invocation.to_string().contains("\"Example User\""));
    }
}
