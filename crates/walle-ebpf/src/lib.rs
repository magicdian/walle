#![no_std]

use walle_common::{PacketAction, RuntimeConfig};

pub mod xdp {
    use core::ptr;
    use walle_common::{
        ICMP_RULE_PAYLOAD_CAPACITY, IcmpMatchType, IcmpRule, PacketAction, RuntimeConfig,
    };

    pub const IPPROTO_TCP: u8 = 6;
    pub const IPPROTO_ICMP: u8 = 1;
    pub const IPPROTO_ICMPV6: u8 = 58;
    pub const ICMPV4_ECHO_REPLY: u8 = 0;
    pub const ICMPV4_ECHO_REQUEST: u8 = 8;
    pub const ICMPV6_ECHO_REQUEST: u8 = 128;
    pub const ICMPV6_ECHO_REPLY: u8 = 129;
    pub const ICMP_ECHO_HEADER_LEN: usize = 8;

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
    pub const fn evaluate_access_with_containment(
        config: &RuntimeConfig,
        is_whitelisted: bool,
        is_blacklisted: bool,
        is_contained: bool,
        protocol: u8,
        tcp_dest_port: u16,
    ) -> PacketAction {
        if is_contained && protocol == IPPROTO_TCP && tcp_dest_port == config.protected_ssh_port {
            PacketAction::Allow
        } else {
            evaluate_access(config, is_whitelisted, is_blacklisted)
        }
    }

    #[must_use]
    pub const fn apply_icmp_policy(
        config: &RuntimeConfig,
        base_action: PacketAction,
        icmp_kind: IcmpPacketKind,
        rule_hit: bool,
    ) -> PacketAction {
        if matches!(base_action, PacketAction::Drop) || matches!(icmp_kind, IcmpPacketKind::NonIcmp)
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
    pub const fn echo_payload_span(
        icmp_kind: IcmpPacketKind,
        icmp_length: usize,
    ) -> Option<(usize, usize)> {
        if !matches!(
            icmp_kind,
            IcmpPacketKind::EchoRequest | IcmpPacketKind::EchoReply
        ) {
            return None;
        }

        if icmp_length <= ICMP_ECHO_HEADER_LEN {
            return None;
        }

        let payload_length = icmp_length - ICMP_ECHO_HEADER_LEN;
        if payload_length > ICMP_RULE_PAYLOAD_CAPACITY {
            return None;
        }

        Some((ICMP_ECHO_HEADER_LEN, payload_length))
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
        ICMPV4_ECHO_REPLY, ICMPV4_ECHO_REQUEST, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST,
        IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IcmpPacketKind, apply_icmp_policy,
        classify_icmp_packet, echo_payload_span, evaluate_access, evaluate_access_with_containment,
        raw_bytes_rule_matches, raw_bytes_rule_matches_buffer,
    };
    use walle_common::{
        AccessMode, ICMP_RULE_PAYLOAD_CAPACITY, IcmpMode, IcmpRule, PacketAction, RuntimeConfig,
    };

    #[test]
    fn ebpf_helper_matches_whitelist_precedence() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, Default::default(), 22, 2222);
        assert_eq!(evaluate_access(&config, true, true), PacketAction::Allow);
    }

    #[test]
    fn containment_overrides_deny_for_protected_ssh() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, Default::default(), 22, 2222);

        assert_eq!(
            evaluate_access_with_containment(&config, false, true, true, IPPROTO_TCP, 22),
            PacketAction::Allow
        );
    }

    #[test]
    fn containment_does_not_override_deny_for_other_tcp_ports() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, Default::default(), 22, 2222);

        assert_eq!(
            evaluate_access_with_containment(&config, false, true, true, IPPROTO_TCP, 80),
            PacketAction::Drop
        );
    }

    #[test]
    fn containment_does_not_override_deny_for_non_tcp_protocols() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, Default::default(), 22, 2222);

        assert_eq!(
            evaluate_access_with_containment(&config, false, true, true, IPPROTO_ICMP, 22),
            PacketAction::Drop
        );
    }

    #[test]
    fn disabled_icmp_policy_keeps_access_verdict() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, IcmpMode::Disabled, 22, 2222);

        assert_eq!(
            apply_icmp_policy(
                &config,
                PacketAction::Allow,
                IcmpPacketKind::EchoRequest,
                false
            ),
            PacketAction::Allow
        );
    }

    #[test]
    fn drop_all_icmp_policy_drops_echo_requests() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, IcmpMode::DropAll, 22, 2222);

        assert_eq!(
            apply_icmp_policy(
                &config,
                PacketAction::Allow,
                IcmpPacketKind::EchoRequest,
                false
            ),
            PacketAction::Drop
        );
    }

    #[test]
    fn drop_all_icmp_policy_keeps_echo_replies() {
        let config = RuntimeConfig::new(AccessMode::BlacklistOnly, IcmpMode::DropAll, 22, 2222);

        assert_eq!(
            apply_icmp_policy(
                &config,
                PacketAction::Allow,
                IcmpPacketKind::EchoReply,
                false
            ),
            PacketAction::Allow
        );
    }

    #[test]
    fn allow_rule_mode_drops_icmp_misses() {
        let config = RuntimeConfig::new(
            AccessMode::BlacklistOnly,
            IcmpMode::AllowRulesActive,
            22,
            2222,
        );

        assert_eq!(
            apply_icmp_policy(
                &config,
                PacketAction::Allow,
                IcmpPacketKind::EchoRequest,
                false
            ),
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
    fn stack_buffer_rule_match_rejects_lengths_beyond_capacity() {
        let rule = IcmpRule::raw_bytes_exact(&[8, 0, 0, 0]).expect("rule should compile");
        let payload = [0u8; ICMP_RULE_PAYLOAD_CAPACITY];

        assert!(!raw_bytes_rule_matches_buffer(
            &rule,
            &payload,
            ICMP_RULE_PAYLOAD_CAPACITY + 1
        ));
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

    #[test]
    fn echo_payload_span_skips_dynamic_echo_header() {
        assert_eq!(
            echo_payload_span(IcmpPacketKind::EchoRequest, 12),
            Some((8, 4))
        );
        assert_eq!(
            echo_payload_span(IcmpPacketKind::EchoReply, 16),
            Some((8, 8))
        );
    }

    #[test]
    fn echo_payload_span_rejects_non_echo_or_empty_payloads() {
        assert_eq!(echo_payload_span(IcmpPacketKind::Other, 12), None);
        assert_eq!(echo_payload_span(IcmpPacketKind::EchoRequest, 8), None);
    }
}
