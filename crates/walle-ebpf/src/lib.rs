#![no_std]

use walle_common::{PacketAction, RuntimeConfig};

pub mod xdp {
    use walle_common::{PacketAction, RuntimeConfig};

    #[must_use]
    pub const fn evaluate_access(
        config: &RuntimeConfig,
        is_whitelisted: bool,
        is_blacklisted: bool,
    ) -> PacketAction {
        config.access_mode.decide(is_whitelisted, is_blacklisted)
    }
}

#[must_use]
pub const fn default_action(config: &RuntimeConfig) -> PacketAction {
    config.default_action
}

#[cfg(test)]
mod tests {
    use super::xdp::evaluate_access;
    use walle_common::{AccessMode, PacketAction, RuntimeConfig};

    #[test]
    fn ebpf_helper_matches_whitelist_precedence() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, Default::default());
        assert_eq!(evaluate_access(&config, true, true), PacketAction::Allow);
    }
}
