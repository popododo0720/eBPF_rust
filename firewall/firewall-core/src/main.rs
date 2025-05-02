use anyhow::{Context as _, anyhow};
use aya::{
    maps::{HashMap, MapData, PerCpuArray, Map},
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{ info, warn };
use tokio::signal;
use std::env;
use sqlx::postgres::PgPoolOptions; 

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

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // export DATABASE_URL="postgres://user:password@host:port/database"
    let database_url = env::var("DATABASE_URL")
        .context("Need to set the DATABASE_URL.")?;
    let pool = PgPoolOptions::new()
        .max_connections(10) 
        .connect(&database_url)
        .await
        .context("Failed connect to the database.")?;
    info!("Connected to the database!");

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?; // 파일

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let Opt { iface } = opt;
    
    let program: &mut Xdp = ebpf
        .program_mut("ebpf_main")
        .ok_or_else(|| anyhow::anyhow!("Program not found"))?
        .try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags")?;


    let map_ref = ebpf
        .map_mut("BLOCKLIST")
        .ok_or_else(|| anyhow!("Map BLOCKLIST not found"))?;

    let mut blocklist: HashMap<&mut MapData, FirewallStruct, u32> = map_ref.try_into()?;

    info!("Select rules from the database...");
    let db_rows = sqlx::query!(
        r#"
        SELECT src_addr, dst_addr, src_port, dst_port, protocol
        FROM firewall_struct
        "# 
    )
    .fetch_all(&pool) 
    .await
    .context("Failed to fetch rows from the database.")?;

    let mut rules_to_block: Vec<FirewallStruct> = Vec::new();
    for row in db_rows {
        let rule = FirewallStruct {
            src_addr: row.src_addr.unwrap_or(0) as u32,
            dst_addr: row.dst_addr.unwrap_or(0) as u32,
            src_port: row.src_port.unwrap_or(0) as u16,
            dst_port: row.dst_port.unwrap_or(0) as u16,
            protocol: row.protocol.unwrap_or(0) as u8,
            _reserved: [0; 3], 
        };
        rules_to_block.push(rule);
    }
    info!("{} rules selected from the database.", rules_to_block.len());

    for rule in rules_to_block {
        match blocklist.insert(rule, 0u32, 0) {
            Ok(_) => {
                info!("Inserted rule: {:?}", rule);
            }
            Err(e) => {
                warn!("규칙 삽입 실패 {:?}: {}", rule, e);
            }
        }
    }

    let drop_count_map_ref = ebpf
        .map("DROP_COUNT") 
        .ok_or_else(|| anyhow!("Map DROP_COUNT not found"))?;
    let drop_count_map: PerCpuArray<_, u64> = PerCpuArray::try_from(drop_count_map_ref)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;

    match drop_count_map.get(&0u32, 0) { 
        Ok(counts_per_cpu) => {
            let total_drops: u64 = counts_per_cpu.iter().sum();
            println!("Total packets dropped: {}", total_drops);
        }
        Err(e) => {
            warn!("Failed to read drop count map: {}", e);
        }
    }

    println!("Exiting...");

    Ok(())
}
