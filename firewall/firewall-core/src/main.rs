use anyhow::{Context as _, anyhow};
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::warn;
use std::net::Ipv4Addr;
use tokio::signal;

use firewall_common::FirewallStruct;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp11s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // memory rlimit setting infinity
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // load ebpf - use build.rs script's 'OUT_DIR'
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?; // 파일
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // get arg and load ebpf program
    let Opt { iface } = opt;
    
    // get main function from firewall-ebpf/main.rs
    let program: &mut Xdp = ebpf
        .program_mut("ebpf_main")
        .ok_or_else(|| anyhow::anyhow!("Program not found"))?
        .try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags")?;

    let mut blocklist: HashMap<_, FirewallStruct, u32> =
        HashMap::try_from(ebpf.map_mut("BLOCKLIST").unwrap())?;

    let block_rule = FirewallStruct {
        src_addr: u32::from_be_bytes(Ipv4Addr::new(192, 168, 0, 99).octets()),
        dst_addr: u32::from_be_bytes(Ipv4Addr::new(10, 0, 0, 1).octets()), 
        src_port: 12345, 
        dst_port: 80,    
        protocol: 6,     
    };

    blocklist.insert(block_rule, 0, 0)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
