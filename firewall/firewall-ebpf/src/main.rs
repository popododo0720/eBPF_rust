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

use firewall_common::FirewallStruct;

#[map] // 
static BLOCKLIST: HashMap<FirewallStruct, u32> =
    HashMap::<FirewallStruct, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn ebpf_main(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
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

fn is_blocked(address: FirewallStruct) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {

    let mut fw_struct = FirewallStruct::default();

    // ethernet header
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    //network-type 0.0.8 버전은 [u8; 4] 형태라 이렇게 못씀 변경필요
    fw_struct.src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    fw_struct.dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    fw_struct.protocol = unsafe { (*ipv4hdr).proto } as u8;
    
    (fw_struct.src_port, fw_struct.dst_port) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        _ => return Err(()),
    };

    let action = if is_blocked(fw_struct) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    // info!(&ctx, "Source IP: {}, Destination IP: {}, Source Port: {}, Destination Port: {}",
    //     source_addr, destination_addr, source_port, destination_port);
    // if action == 1 {
        info!(&ctx, "srcip: {:i}:{}, dstip: {:i}:{}, PROTO: {}, ACTION: {}",
        fw_struct.src_addr, fw_struct.src_port, fw_struct.dst_addr, fw_struct.dst_port, fw_struct.protocol, action);
    // }

    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// #[link_section = "license"]
// #[no_mangle]
// static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
#[unsafe(link_section = "license")] 
#[unsafe(no_mangle)]             
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";