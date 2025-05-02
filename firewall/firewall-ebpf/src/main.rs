#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, 
    macros::{map, xdp}, 
    programs::XdpContext, 
    maps::{HashMap, PerCpuArray},
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

#[map] 
static BLOCKLIST: HashMap<FirewallStruct, u32> =
    HashMap::<FirewallStruct, u32>::with_max_entries(1024, 0);

#[map]
static DROP_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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

fn is_blocked(packet_info: FirewallStruct) -> bool {
    let mut key_to_check = FirewallStruct {
        src_addr: packet_info.src_addr, 
        dst_addr: packet_info.dst_addr,
        src_port: 0,                 
        dst_port: packet_info.dst_port,                
        protocol: 0,                   
        _reserved: [0; 3],
    };

    // 1. 정확한 IP 주소 조합 확인 (포트/프로토콜 무시)
    if unsafe { BLOCKLIST.get(&key_to_check).is_some() } {
        return true;
    }

    // 2. 목적지 IP 주소만 와일드카드(0)인 규칙 확인 (포트/프로토콜 무시)
    key_to_check.dst_addr = 0; 
    if unsafe { BLOCKLIST.get(&key_to_check).is_some() } {
        return true;
    }

    // 3. 출발지 IP 주소만 와일드카드(0)인 규칙 확인 (포트/프로토콜 무시)
    key_to_check.src_addr = 0; 
    if unsafe { BLOCKLIST.get(&key_to_check).is_some() } {
        return true;
    }

    // 위의 어떤 IP 조합 규칙과도 일치하지 않으면 차단하지 않음
    false
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

    fw_struct.src_addr = unsafe { (*ipv4hdr).src_addr };

    fw_struct.dst_addr = unsafe { (*ipv4hdr).dst_addr };
    fw_struct.protocol = unsafe { (*ipv4hdr).proto } as u8;
    
    (fw_struct.src_port, fw_struct.dst_port) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                unsafe { (*tcphdr).source },
                unsafe { (*tcphdr).dest },
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                unsafe { (*udphdr).source },
                unsafe { (*udphdr).dest },
            )
        }
        _ => return Err(()),
    };

    let action = if is_blocked(fw_struct) {
        let index: u32 = 0; 
        let count_ptr = unsafe { DROP_COUNT.get_ptr_mut(index) };

        let mut current_cpu_count: u64 = 0; 
        if let Some(ptr) = count_ptr {
            unsafe {
                *ptr += 1;
                current_cpu_count = *ptr;
            }
        } else {
            info!(&ctx, "drop (counter error)");
        }

        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")] 
#[unsafe(no_mangle)]             
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";