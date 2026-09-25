mod command;
mod interfaces;
#[doc(hidden)]
pub mod publication;

pub use command::{Invocation, NetworkTool};
pub use interfaces::{
    AddressView, InterfaceError, InterfaceView, LocalAddress, LocalInterface, interface_views,
    local_interfaces, write_interfaces, write_interfaces_colored,
};
pub use v6alias_core::{
    Alias, AliasError, Config, ConfigError, Profile, UlaPrefix, UlaPrefixError,
};
