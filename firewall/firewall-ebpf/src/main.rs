#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, 
    macros::{map, xdp}, 
    programs::XdpContext, 
    maps::HashMap,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use firewall_common::{PacketInfo, PolicyKeyL3, PolicyKeyL4};

// ID 없는경우 기본 ID
const WORLD_ID: u32 = 0;
const EBPF_ACTION_DROP: u32 = 1;
const EBPF_ACTION_PASS: u32 = 2;

// --- ID 기반 맵  ---
#[map]
static IP_ID_MAP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(4096, 0);
// --- L4 ---
#[map]
static BLOCK_POLICY_L4_MAP: HashMap<PolicyKeyL4, u32> = HashMap::<PolicyKeyL4, u32>::with_max_entries(8192, 0);
// --- L3 ---
#[map]
static BLOCK_POLICY_L3_MAP: HashMap<PolicyKeyL3, u32> = HashMap::<PolicyKeyL3, u32>::with_max_entries(2048, 0);

#[xdp]
pub fn ebpf_main(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(())
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // ethernet header
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let protocol_enum = unsafe { (*ipv4hdr).proto };
    let protocol = protocol_enum as u8;

    let dst_port = match protocol_enum {
        IpProto::Tcp => unsafe { *ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? }.dest,
        IpProto::Udp => unsafe { *ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? }.dest,
        _ => return Ok(xdp_action::XDP_PASS), 
    };

    let src_id = unsafe { IP_ID_MAP.get(&src_addr).copied().unwrap_or(WORLD_ID) };
    let dst_id = unsafe { IP_ID_MAP.get(&dst_addr).copied().unwrap_or(WORLD_ID) };

    let policy_key_l4 = PolicyKeyL4 { 
        src_id, dst_id, dst_port, protocol, _padding: 0 
    };
    if let Some(action_val_ptr) = unsafe { BLOCK_POLICY_L4_MAP.get(&policy_key_l4) } {
        let action_val = *action_val_ptr;
        if action_val == EBPF_ACTION_DROP {
            info!(&ctx, "Blocked by L4 policy (action={})", action_val);
            return Ok(xdp_action::XDP_DROP);
        } else if action_val == EBPF_ACTION_PASS {
            info!(&ctx, "Passed by L4 policy (action={})", action_val);
            return Ok(xdp_action::XDP_PASS);
        }
        return Ok(xdp_action::XDP_PASS);
    }

    let policy_key_l3 = PolicyKeyL3 { 
        src_id, dst_id 
    };
    if let Some(action_val_ptr) = unsafe { BLOCK_POLICY_L3_MAP.get(&policy_key_l3) } { // L3 맵 조회 시 값 확인 추가
        let action_val = *action_val_ptr;
        if action_val == EBPF_ACTION_DROP {
            info!(&ctx, "Blocked by L3 policy (action={})", action_val);
            return Ok(xdp_action::XDP_DROP);
        } else if action_val == EBPF_ACTION_PASS {
            info!(&ctx, "Passed by L3 policy (action={})", action_val);
            return Ok(xdp_action::XDP_PASS);
        }
        return Ok(xdp_action::XDP_PASS);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")] 
#[unsafe(no_mangle)]             
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";