#![no_std]

use walle_common::{PacketAction, RuntimeConfig};

pub mod xdp {
    use core::ptr;
    use walle_common::{IcmpMatchType, IcmpRule, PacketAction, RuntimeConfig, ICMP_RULE_PAYLOAD_CAPACITY};

    pub const IPPROTO_ICMP: u8 = 1;
    pub const IPPROTO_ICMPV6: u8 = 58;
    pub const ICMPV4_ECHO_REPLY: u8 = 0;
    pub const ICMPV4_ECHO_REQUEST: u8 = 8;
    pub const ICMPV6_ECHO_REQUEST: u8 = 128;
    pub const ICMPV6_ECHO_REPLY: u8 = 129;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum IcmpPacketKind {
        NonIcmp,
        EchoRequest,
        EchoReply,
        Other,
    }

    #[must_use]
    pub const fn evaluate_access(
        config: &RuntimeConfig,
        is_whitelisted: bool,
        is_blacklisted: bool,
    ) -> PacketAction {
        config.access_mode.decide(is_whitelisted, is_blacklisted)
    }

    #[must_use]
    pub const fn apply_icmp_policy(
        config: &RuntimeConfig,
        base_action: PacketAction,
        icmp_kind: IcmpPacketKind,
        rule_hit: bool,
    ) -> PacketAction {
        if matches!(base_action, PacketAction::Drop)
            || matches!(icmp_kind, IcmpPacketKind::NonIcmp)
        {
            return base_action;
        }

        match config.icmp_mode {
            walle_common::IcmpMode::Disabled => base_action,
            walle_common::IcmpMode::DropAll => {
                if matches!(icmp_kind, IcmpPacketKind::EchoReply) {
                    base_action
                } else {
                    PacketAction::Drop
                }
            }
            walle_common::IcmpMode::AllowRulesActive => {
                if rule_hit {
                    PacketAction::Allow
                } else {
                    PacketAction::Drop
                }
            }
        }
    }

    #[must_use]
    pub const fn is_icmp_protocol(protocol: u8) -> bool {
        matches!(protocol, IPPROTO_ICMP | IPPROTO_ICMPV6)
    }

    #[must_use]
    pub const fn classify_icmp_packet(protocol: u8, icmp_type: u8) -> IcmpPacketKind {
        match protocol {
            IPPROTO_ICMP => match icmp_type {
                ICMPV4_ECHO_REQUEST => IcmpPacketKind::EchoRequest,
                ICMPV4_ECHO_REPLY => IcmpPacketKind::EchoReply,
                _ => IcmpPacketKind::Other,
            },
            IPPROTO_ICMPV6 => match icmp_type {
                ICMPV6_ECHO_REQUEST => IcmpPacketKind::EchoRequest,
                ICMPV6_ECHO_REPLY => IcmpPacketKind::EchoReply,
                _ => IcmpPacketKind::Other,
            },
            _ => IcmpPacketKind::NonIcmp,
        }
    }

    #[must_use]
    pub fn raw_bytes_rule_matches(rule: &IcmpRule, payload: &[u8]) -> bool {
        raw_bytes_rule_matches_parts(rule, payload.as_ptr(), payload.len())
    }

    #[must_use]
    pub fn raw_bytes_rule_matches_buffer(
        rule: &IcmpRule,
        payload: &[u8; ICMP_RULE_PAYLOAD_CAPACITY],
        payload_length: usize,
    ) -> bool {
        if payload_length > payload.len() {
            return false;
        }

        raw_bytes_rule_matches_parts(rule, payload.as_ptr(), payload_length)
    }

    fn raw_bytes_rule_matches_parts(
        rule: &IcmpRule,
        payload_ptr: *const u8,
        payload_length: usize,
    ) -> bool {
        if rule.enabled == 0 || rule.match_type != IcmpMatchType::RawBytesExact {
            return false;
        }

        let expected_len = rule.payload_length as usize;
        if expected_len != payload_length || expected_len > rule.payload.len() {
            return false;
        }

        // Safety: lengths were validated above, so both regions are readable for expected_len.
        unsafe {
            ptr::addr_eq(rule.payload.as_ptr(), payload_ptr)
                || compare_bytes(rule.payload.as_ptr(), payload_ptr, expected_len)
        }
    }

    unsafe fn compare_bytes(left: *const u8, right: *const u8, len: usize) -> bool {
        let mut index = 0;
        while index < len {
            // Safety: caller guarantees both pointers are readable for len bytes.
            if unsafe { ptr::read(left.add(index)) } != unsafe { ptr::read(right.add(index)) } {
                return false;
            }
            index += 1;
        }

        true
    }
}

#[must_use]
pub const fn default_action(config: &RuntimeConfig) -> PacketAction {
    config.default_action
}

#[cfg(test)]
mod tests {
    use super::xdp::{
        apply_icmp_policy, classify_icmp_packet, evaluate_access, raw_bytes_rule_matches,
        raw_bytes_rule_matches_buffer, IcmpPacketKind, ICMPV4_ECHO_REPLY, ICMPV4_ECHO_REQUEST,
        ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST, IPPROTO_ICMP, IPPROTO_ICMPV6,
    };
    use walle_common::{
        AccessMode, IcmpMode, IcmpRule, PacketAction, RuntimeConfig, ICMP_RULE_PAYLOAD_CAPACITY,
    };

    #[test]
    fn ebpf_helper_matches_whitelist_precedence() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, Default::default());
        assert_eq!(evaluate_access(&config, true, true), PacketAction::Allow);
    }

    #[test]
    fn disabled_icmp_policy_keeps_access_verdict() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, IcmpMode::Disabled);

        assert_eq!(
            apply_icmp_policy(&config, PacketAction::Allow, IcmpPacketKind::EchoRequest, false),
            PacketAction::Allow
        );
    }

    #[test]
    fn drop_all_icmp_policy_drops_echo_requests() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, IcmpMode::DropAll);

        assert_eq!(
            apply_icmp_policy(&config, PacketAction::Allow, IcmpPacketKind::EchoRequest, false),
            PacketAction::Drop
        );
    }

    #[test]
    fn drop_all_icmp_policy_keeps_echo_replies() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, IcmpMode::DropAll);

        assert_eq!(
            apply_icmp_policy(&config, PacketAction::Allow, IcmpPacketKind::EchoReply, false),
            PacketAction::Allow
        );
    }

    #[test]
    fn allow_rule_mode_drops_icmp_misses() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, IcmpMode::AllowRulesActive);

        assert_eq!(
            apply_icmp_policy(&config, PacketAction::Allow, IcmpPacketKind::EchoRequest, false),
            PacketAction::Drop
        );
    }

    #[test]
    fn allow_rule_mode_keeps_exact_match() {
        let rule = IcmpRule::raw_bytes_exact(&[8, 0, 0, 0]).expect("rule should compile");

        assert!(raw_bytes_rule_matches(&rule, &[8, 0, 0, 0]));
        assert!(!raw_bytes_rule_matches(&rule, &[8, 0, 0]));
        assert!(!raw_bytes_rule_matches(&rule, &[8, 0, 0, 1]));
    }

    #[test]
    fn stack_buffer_rule_match_respects_explicit_length() {
        let rule = IcmpRule::raw_bytes_exact(&[8, 0, 0, 0]).expect("rule should compile");
        let mut payload = [0u8; ICMP_RULE_PAYLOAD_CAPACITY];
        payload[..4].copy_from_slice(&[8, 0, 0, 0]);

        assert!(raw_bytes_rule_matches_buffer(&rule, &payload, 4));
        assert!(!raw_bytes_rule_matches_buffer(&rule, &payload, 3));
    }

    #[test]
    fn classify_icmp_packet_distinguishes_request_and_reply() {
        assert_eq!(
            classify_icmp_packet(IPPROTO_ICMP, ICMPV4_ECHO_REQUEST),
            IcmpPacketKind::EchoRequest
        );
        assert_eq!(
            classify_icmp_packet(IPPROTO_ICMP, ICMPV4_ECHO_REPLY),
            IcmpPacketKind::EchoReply
        );
        assert_eq!(
            classify_icmp_packet(IPPROTO_ICMPV6, ICMPV6_ECHO_REQUEST),
            IcmpPacketKind::EchoRequest
        );
        assert_eq!(
            classify_icmp_packet(IPPROTO_ICMPV6, ICMPV6_ECHO_REPLY),
            IcmpPacketKind::EchoReply
        );
    }
}
