#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, xdp_action},
    macros::{classifier, map, xdp},
    maps::{Array, HashMap},
    programs::{TcContext, XdpContext},
};
use core::{mem, ptr};
use walle_common::{
    ALLOW_MAP_CAPACITY, BanEntryV4, CONFIG_MAP_CAPACITY, CONFIG_MAP_KEY, DENY_MAP_CAPACITY,
    ICMP_RULE_MAP_CAPACITY, ICMP_RULE_PAYLOAD_CAPACITY, IcmpMatchType, IcmpRule, Ipv4AddrKey,
    Ipv6AddrKey, PacketAction, RuntimeConfig, STATS_MAP_CAPACITY, STATS_MAP_KEY, SshContainEntry,
    StatsCounters,
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

#[map(name = "contain_v4")]
static CONTAIN_V4: HashMap<Ipv4AddrKey, SshContainEntry> = HashMap::pinned(DENY_MAP_CAPACITY, 0);

#[map(name = "contain_v6")]
static CONTAIN_V6: HashMap<Ipv6AddrKey, SshContainEntry> = HashMap::pinned(DENY_MAP_CAPACITY, 0);

#[map(name = "icmp_rules")]
static ICMP_RULES: HashMap<IcmpRule, u8> = HashMap::pinned(ICMP_RULE_MAP_CAPACITY, 0);

#[map(name = "stats")]
static STATS: Array<StatsCounters> = Array::pinned(STATS_MAP_CAPACITY, 0);

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_HEADER_LEN: usize = mem::size_of::<EthernetHeader>();
const IPV6_HEADER_LEN: usize = mem::size_of::<Ipv6Header>();
const TCP_DEST_OFFSET: usize = 2;
const TCP_SOURCE_OFFSET: usize = 0;
const TCP_CHECK_OFFSET: usize = 16;

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

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpHeader {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
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
    let is_contained = unsafe { CONTAIN_V4.get(&key).is_some() };
    record_access_hits(is_whitelisted, is_blacklisted);
    let protocol = ip.protocol;
    let allow_contained_ssh = should_allow_contained_ssh_ipv4(
        ctx,
        config,
        is_whitelisted,
        is_blacklisted,
        protocol,
        header_length,
        is_contained,
    )?;
    let base_action = allow_contained_ssh;
    let icmp_kind = classify_ipv4_icmp_packet(ctx, protocol, header_length)?;
    let rule_hit = maybe_match_icmp_rules(
        ctx,
        config,
        base_action,
        icmp_kind,
        ETH_HEADER_LEN + header_length,
        usize::from(total_length) - header_length,
    )?;

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
    let is_contained = unsafe { CONTAIN_V6.get(&key).is_some() };
    record_access_hits(is_whitelisted, is_blacklisted);
    let protocol = ip.next_header;
    let allow_contained_ssh = should_allow_contained_ssh_ipv6(
        ctx,
        config,
        is_whitelisted,
        is_blacklisted,
        protocol,
        is_contained,
    )?;
    let base_action = allow_contained_ssh;
    let icmp_kind = classify_ipv6_icmp_packet(ctx, protocol)?;
    let rule_hit = maybe_match_icmp_rules(
        ctx,
        config,
        base_action,
        icmp_kind,
        ETH_HEADER_LEN + IPV6_HEADER_LEN,
        usize::from(u16::from_be(ip.payload_length)),
    )?;

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

fn should_allow_contained_ssh_ipv4(
    ctx: &XdpContext,
    config: &RuntimeConfig,
    is_whitelisted: bool,
    is_blacklisted: bool,
    protocol: u8,
    header_length: usize,
    is_contained: bool,
) -> Result<PacketAction, ()> {
    if !is_contained || protocol != walle_ebpf::xdp::IPPROTO_TCP {
        return Ok(walle_ebpf::xdp::evaluate_access(
            config,
            is_whitelisted,
            is_blacklisted,
        ));
    }

    let tcp_offset = ETH_HEADER_LEN + header_length;
    let tcp: TcpHeader = read_unaligned(ctx, tcp_offset)?;
    Ok(walle_ebpf::xdp::evaluate_access_with_containment(
        config,
        is_whitelisted,
        is_blacklisted,
        is_contained,
        protocol,
        u16::from_be(tcp.dest),
    ))
}

fn should_allow_contained_ssh_ipv6(
    ctx: &XdpContext,
    config: &RuntimeConfig,
    is_whitelisted: bool,
    is_blacklisted: bool,
    protocol: u8,
    is_contained: bool,
) -> Result<PacketAction, ()> {
    if !is_contained || protocol != walle_ebpf::xdp::IPPROTO_TCP {
        return Ok(walle_ebpf::xdp::evaluate_access(
            config,
            is_whitelisted,
            is_blacklisted,
        ));
    }

    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let tcp: TcpHeader = read_unaligned(ctx, tcp_offset)?;
    Ok(walle_ebpf::xdp::evaluate_access_with_containment(
        config,
        is_whitelisted,
        is_blacklisted,
        is_contained,
        protocol,
        u16::from_be(tcp.dest),
    ))
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

fn maybe_match_icmp_rules(
    ctx: &XdpContext,
    config: &RuntimeConfig,
    base_action: PacketAction,
    icmp_kind: walle_ebpf::xdp::IcmpPacketKind,
    icmp_offset: usize,
    icmp_length: usize,
) -> Result<bool, ()> {
    if !matches!(config.icmp_mode, walle_common::IcmpMode::AllowRulesActive)
        || matches!(base_action, PacketAction::Drop)
    {
        return Ok(false);
    }

    let Some((payload_start, payload_length)) =
        walle_ebpf::xdp::echo_payload_span(icmp_kind, icmp_length)
    else {
        return Ok(false);
    };

    let mut lookup_rule = IcmpRule {
        match_type: IcmpMatchType::RawBytesExact,
        payload_length: payload_length as u16,
        enabled: 1,
        reserved: 0,
        payload: [0u8; ICMP_RULE_PAYLOAD_CAPACITY],
    };
    let mut payload_index = 0;
    while payload_index < payload_length {
        lookup_rule.payload[payload_index] =
            read_u8(ctx, icmp_offset + payload_start + payload_index)?;
        payload_index += 1;
    }

    Ok(unsafe { ICMP_RULES.get(&lookup_rule).is_some() })
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

#[classifier]
pub fn walle_tc_ingress(ctx: TcContext) -> i32 {
    match try_walle_tc_ingress(ctx) {
        Ok(action) => action,
        Err(action) => action,
    }
}

#[classifier]
pub fn walle_tc_egress(ctx: TcContext) -> i32 {
    match try_walle_tc_egress(ctx) {
        Ok(action) => action,
        Err(action) => action,
    }
}

fn try_walle_tc_ingress(mut ctx: TcContext) -> Result<i32, i32> {
    let config = CONFIG.get(CONFIG_MAP_KEY).ok_or(TC_ACT_PIPE)?;
    let ethernet: EthernetHeader = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;

    match u16::from_be(ethernet.ether_type) {
        ETH_P_IPV4 => rewrite_ingress_ipv4(&mut ctx, config),
        ETH_P_IPV6 => rewrite_ingress_ipv6(&mut ctx, config),
        _ => Ok(TC_ACT_PIPE),
    }
}

fn try_walle_tc_egress(mut ctx: TcContext) -> Result<i32, i32> {
    let config = CONFIG.get(CONFIG_MAP_KEY).ok_or(TC_ACT_PIPE)?;
    let ethernet: EthernetHeader = ctx.load(0).map_err(|_| TC_ACT_PIPE)?;

    match u16::from_be(ethernet.ether_type) {
        ETH_P_IPV4 => rewrite_egress_ipv4(&mut ctx, config),
        ETH_P_IPV6 => rewrite_egress_ipv6(&mut ctx, config),
        _ => Ok(TC_ACT_PIPE),
    }
}

fn rewrite_ingress_ipv4(ctx: &mut TcContext, config: &RuntimeConfig) -> Result<i32, i32> {
    let ip: Ipv4Header = ctx.load(ETH_HEADER_LEN).map_err(|_| TC_ACT_PIPE)?;
    let header_length = ipv4_header_length(ip.version_ihl).map_err(|_| TC_ACT_PIPE)?;

    if ip.protocol != walle_ebpf::xdp::IPPROTO_TCP {
        return Ok(TC_ACT_PIPE);
    }

    if unsafe { CONTAIN_V4.get(&Ipv4AddrKey::new(ip.source)).is_none() } {
        return Ok(TC_ACT_PIPE);
    }

    let tcp_offset = ETH_HEADER_LEN + header_length;
    let tcp: TcpHeader = ctx.load(tcp_offset).map_err(|_| TC_ACT_PIPE)?;
    if u16::from_be(tcp.dest) != config.protected_ssh_port {
        return Ok(TC_ACT_PIPE);
    }

    let new_port = config.ssh_jail_port.to_be();
    ctx.l4_csum_replace(
        tcp_offset + TCP_CHECK_OFFSET,
        tcp.dest as u64,
        new_port as u64,
        2,
    )
    .map_err(|_| TC_ACT_PIPE)?;
    ctx.store(tcp_offset + TCP_DEST_OFFSET, &new_port, 0)
        .map_err(|_| TC_ACT_PIPE)?;

    Ok(TC_ACT_PIPE)
}

fn rewrite_ingress_ipv6(ctx: &mut TcContext, config: &RuntimeConfig) -> Result<i32, i32> {
    let ip: Ipv6Header = ctx.load(ETH_HEADER_LEN).map_err(|_| TC_ACT_PIPE)?;
    if ip.next_header != walle_ebpf::xdp::IPPROTO_TCP {
        return Ok(TC_ACT_PIPE);
    }

    if unsafe { CONTAIN_V6.get(&Ipv6AddrKey::new(ip.source)).is_none() } {
        return Ok(TC_ACT_PIPE);
    }

    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let tcp: TcpHeader = ctx.load(tcp_offset).map_err(|_| TC_ACT_PIPE)?;
    if u16::from_be(tcp.dest) != config.protected_ssh_port {
        return Ok(TC_ACT_PIPE);
    }

    let new_port = config.ssh_jail_port.to_be();
    ctx.l4_csum_replace(
        tcp_offset + TCP_CHECK_OFFSET,
        tcp.dest as u64,
        new_port as u64,
        2,
    )
    .map_err(|_| TC_ACT_PIPE)?;
    ctx.store(tcp_offset + TCP_DEST_OFFSET, &new_port, 0)
        .map_err(|_| TC_ACT_PIPE)?;

    Ok(TC_ACT_PIPE)
}

fn rewrite_egress_ipv4(ctx: &mut TcContext, config: &RuntimeConfig) -> Result<i32, i32> {
    let ip: Ipv4Header = ctx.load(ETH_HEADER_LEN).map_err(|_| TC_ACT_PIPE)?;
    let header_length = ipv4_header_length(ip.version_ihl).map_err(|_| TC_ACT_PIPE)?;

    if ip.protocol != walle_ebpf::xdp::IPPROTO_TCP {
        return Ok(TC_ACT_PIPE);
    }

    if unsafe { CONTAIN_V4.get(&Ipv4AddrKey::new(ip.destination)).is_none() } {
        return Ok(TC_ACT_PIPE);
    }

    let tcp_offset = ETH_HEADER_LEN + header_length;
    let tcp: TcpHeader = ctx.load(tcp_offset).map_err(|_| TC_ACT_PIPE)?;
    if u16::from_be(tcp.source) != config.ssh_jail_port {
        return Ok(TC_ACT_PIPE);
    }

    let new_port = config.protected_ssh_port.to_be();
    ctx.l4_csum_replace(
        tcp_offset + TCP_CHECK_OFFSET,
        tcp.source as u64,
        new_port as u64,
        2,
    )
    .map_err(|_| TC_ACT_PIPE)?;
    ctx.store(tcp_offset + TCP_SOURCE_OFFSET, &new_port, 0)
        .map_err(|_| TC_ACT_PIPE)?;

    Ok(TC_ACT_PIPE)
}

fn rewrite_egress_ipv6(ctx: &mut TcContext, config: &RuntimeConfig) -> Result<i32, i32> {
    let ip: Ipv6Header = ctx.load(ETH_HEADER_LEN).map_err(|_| TC_ACT_PIPE)?;
    if ip.next_header != walle_ebpf::xdp::IPPROTO_TCP {
        return Ok(TC_ACT_PIPE);
    }

    if unsafe { CONTAIN_V6.get(&Ipv6AddrKey::new(ip.destination)).is_none() } {
        return Ok(TC_ACT_PIPE);
    }

    let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let tcp: TcpHeader = ctx.load(tcp_offset).map_err(|_| TC_ACT_PIPE)?;
    if u16::from_be(tcp.source) != config.ssh_jail_port {
        return Ok(TC_ACT_PIPE);
    }

    let new_port = config.protected_ssh_port.to_be();
    ctx.l4_csum_replace(
        tcp_offset + TCP_CHECK_OFFSET,
        tcp.source as u64,
        new_port as u64,
        2,
    )
    .map_err(|_| TC_ACT_PIPE)?;
    ctx.store(tcp_offset + TCP_SOURCE_OFFSET, &new_port, 0)
        .map_err(|_| TC_ACT_PIPE)?;

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
