#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use core::{mem, ptr};
use walle_common::{
    ALLOW_MAP_CAPACITY, BanEntryV4, CONFIG_MAP_CAPACITY, CONFIG_MAP_KEY, DENY_MAP_CAPACITY,
    ICMP_RULE_MAP_CAPACITY, IcmpRule, Ipv4AddrKey, Ipv6AddrKey, PacketAction, RuntimeConfig,
    STATS_MAP_CAPACITY, STATS_MAP_KEY, StatsCounters,
};

#[map(name = "config")]
static CONFIG: Array<RuntimeConfig> = Array::pinned(CONFIG_MAP_CAPACITY, 0);

#[map(name = "allow_v4")]
static ALLOW_V4: HashMap<Ipv4AddrKey, u8> = HashMap::pinned(ALLOW_MAP_CAPACITY, 0);

#[map(name = "allow_v6")]
static ALLOW_V6: HashMap<Ipv6AddrKey, u8> = HashMap::pinned(ALLOW_MAP_CAPACITY, 0);

#[map(name = "deny_v4")]
static DENY_V4: HashMap<Ipv4AddrKey, BanEntryV4> = HashMap::pinned(DENY_MAP_CAPACITY, 0);

#[map(name = "deny_v6")]
static DENY_V6: HashMap<Ipv6AddrKey, BanEntryV4> = HashMap::pinned(DENY_MAP_CAPACITY, 0);

#[map(name = "icmp_rules")]
static ICMP_RULES: Array<IcmpRule> = Array::pinned(ICMP_RULE_MAP_CAPACITY, 0);

#[map(name = "stats")]
static STATS: Array<StatsCounters> = Array::pinned(STATS_MAP_CAPACITY, 0);

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_HEADER_LEN: usize = mem::size_of::<EthernetHeader>();
const IPV6_HEADER_LEN: usize = mem::size_of::<Ipv6Header>();

#[repr(C)]
#[derive(Clone, Copy)]
struct EthernetHeader {
    destination: [u8; 6],
    source: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source: [u8; 4],
    destination: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv6Header {
    version_tc_flow: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    source: [u8; 16],
    destination: [u8; 16],
}

#[xdp]
pub fn walle_ingress(ctx: XdpContext) -> u32 {
    match try_walle_ingress(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_parser_failures();
            xdp_action::XDP_PASS
        }
    }
}

fn try_walle_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let config = CONFIG.get(CONFIG_MAP_KEY).ok_or(())?;
    let ethernet = read_unaligned::<EthernetHeader>(ctx, 0)?;

    let verdict = match u16::from_be(ethernet.ether_type) {
        ETH_P_IPV4 => evaluate_ipv4(ctx, config)?,
        ETH_P_IPV6 => evaluate_ipv6(ctx, config)?,
        _ => PacketAction::Allow,
    };

    record_verdict(verdict_metrics(verdict));
    Ok(packet_action_to_xdp(verdict))
}

fn evaluate_ipv4(ctx: &XdpContext, config: &RuntimeConfig) -> Result<PacketAction, ()> {
    let ip = read_unaligned::<Ipv4Header>(ctx, ETH_HEADER_LEN)?;
    let header_length = ipv4_header_length(ip.version_ihl)?;
    let total_length = u16::from_be(ip.total_length);
    if usize::from(total_length) < header_length {
        return Err(());
    }

    let key = Ipv4AddrKey::new(ip.source);
    let is_whitelisted = unsafe { ALLOW_V4.get(&key).is_some() };
    let is_blacklisted = unsafe { DENY_V4.get(&key).is_some() };
    record_access_hits(is_whitelisted, is_blacklisted);
    let base_action = walle_ebpf::xdp::evaluate_access(config, is_whitelisted, is_blacklisted);
    let protocol = ip.protocol;
    let icmp_kind = classify_ipv4_icmp_packet(ctx, protocol, header_length)?;
    // TODO: restore verifier-safe exact payload matching for AllowRulesActive.
    let rule_hit = false;

    if rule_hit {
        increment_icmp_rule_hits();
    }

    Ok(walle_ebpf::xdp::apply_icmp_policy(
        config,
        base_action,
        icmp_kind,
        rule_hit,
    ))
}

fn evaluate_ipv6(ctx: &XdpContext, config: &RuntimeConfig) -> Result<PacketAction, ()> {
    let ip = read_unaligned::<Ipv6Header>(ctx, ETH_HEADER_LEN)?;
    let key = Ipv6AddrKey::new(ip.source);
    let is_whitelisted = unsafe { ALLOW_V6.get(&key).is_some() };
    let is_blacklisted = unsafe { DENY_V6.get(&key).is_some() };
    record_access_hits(is_whitelisted, is_blacklisted);
    let base_action = walle_ebpf::xdp::evaluate_access(config, is_whitelisted, is_blacklisted);
    let protocol = ip.next_header;
    let icmp_kind = classify_ipv6_icmp_packet(ctx, protocol)?;
    // TODO: restore verifier-safe exact payload matching for AllowRulesActive.
    let rule_hit = false;

    if rule_hit {
        increment_icmp_rule_hits();
    }

    Ok(walle_ebpf::xdp::apply_icmp_policy(
        config,
        base_action,
        icmp_kind,
        rule_hit,
    ))
}

fn packet_action_to_xdp(action: PacketAction) -> u32 {
    match action {
        PacketAction::Allow => xdp_action::XDP_PASS,
        PacketAction::Drop => xdp_action::XDP_DROP,
    }
}

fn verdict_metrics(action: PacketAction) -> VerdictMetrics {
    match action {
        PacketAction::Allow => VerdictMetrics {
            allowed: 1,
            dropped: 0,
        },
        PacketAction::Drop => VerdictMetrics {
            allowed: 0,
            dropped: 1,
        },
    }
}

struct VerdictMetrics {
    allowed: u64,
    dropped: u64,
}

fn record_verdict(metrics: VerdictMetrics) {
    if let Some(stats) = STATS.get_ptr_mut(STATS_MAP_KEY) {
        unsafe {
            (*stats).packets_allowed = (*stats).packets_allowed.saturating_add(metrics.allowed);
            (*stats).packets_dropped = (*stats).packets_dropped.saturating_add(metrics.dropped);
        }
    }
}

fn increment_parser_failures() {
    if let Some(stats) = STATS.get_ptr_mut(STATS_MAP_KEY) {
        unsafe {
            (*stats).parser_failures = (*stats).parser_failures.saturating_add(1);
        }
    }
}

fn record_access_hits(is_whitelisted: bool, is_blacklisted: bool) {
    if let Some(stats) = STATS.get_ptr_mut(STATS_MAP_KEY) {
        unsafe {
            if is_whitelisted {
                (*stats).allowlist_hits = (*stats).allowlist_hits.saturating_add(1);
            }
            if is_blacklisted {
                (*stats).denylist_hits = (*stats).denylist_hits.saturating_add(1);
            }
        }
    }
}

fn increment_icmp_rule_hits() {
    if let Some(stats) = STATS.get_ptr_mut(STATS_MAP_KEY) {
        unsafe {
            (*stats).icmp_rule_hits = (*stats).icmp_rule_hits.saturating_add(1);
        }
    }
}

fn ipv4_header_length(version_ihl: u8) -> Result<usize, ()> {
    let header_length = usize::from(version_ihl & 0x0f) * 4;
    if header_length < mem::size_of::<Ipv4Header>() {
        return Err(());
    }

    Ok(header_length)
}

fn classify_ipv4_icmp_packet(
    ctx: &XdpContext,
    protocol: u8,
    header_length: usize,
) -> Result<walle_ebpf::xdp::IcmpPacketKind, ()> {
    if !walle_ebpf::xdp::is_icmp_protocol(protocol) {
        return Ok(walle_ebpf::xdp::IcmpPacketKind::NonIcmp);
    }

    let icmp_type = read_u8(ctx, ETH_HEADER_LEN + header_length)?;
    Ok(walle_ebpf::xdp::classify_icmp_packet(protocol, icmp_type))
}

fn classify_ipv6_icmp_packet(
    ctx: &XdpContext,
    protocol: u8,
) -> Result<walle_ebpf::xdp::IcmpPacketKind, ()> {
    if !walle_ebpf::xdp::is_icmp_protocol(protocol) {
        return Ok(walle_ebpf::xdp::IcmpPacketKind::NonIcmp);
    }

    let icmp_type = read_u8(ctx, ETH_HEADER_LEN + IPV6_HEADER_LEN)?;
    Ok(walle_ebpf::xdp::classify_icmp_packet(protocol, icmp_type))
}

fn read_ptr<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let size = mem::size_of::<T>();
    let boundary = start
        .checked_add(offset)
        .and_then(|value| value.checked_add(size))
        .ok_or(())?;

    if boundary > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn read_unaligned<T: Copy>(ctx: &XdpContext, offset: usize) -> Result<T, ()> {
    let ptr = read_ptr::<T>(ctx, offset)?;
    // Safety: read_ptr verified the full object is within packet bounds.
    Ok(unsafe { ptr::read_unaligned(ptr) })
}

fn read_u8(ctx: &XdpContext, offset: usize) -> Result<u8, ()> {
    read_unaligned::<u8>(ctx, offset)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
