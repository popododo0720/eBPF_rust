use anyhow::{Context as _, anyhow};
use aya::{
    maps::{HashMap as AyaHashMap, MapData, Map},
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{ info, warn };
use tokio::signal;
use std::env;
use sqlx::postgres::PgPoolOptions; 
use std::net::Ipv4Addr;
use std::collections::HashMap as StdHashMap;

use firewall_common::{PolicyKeyL3, PolicyKeyL4};

// ID가 없는 IP에 대한 기본 ID 
const WORLD_ID: u32 = 0;

const DB_ACTION_DROP: i16 = 0; 
const EBPF_ACTION_DROP: u32 = 1; 
const EBPF_ACTION_PASS: u32 = 2;

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
    )))?; 

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

        //
        // 문제구간

   // --- eBPF 맵 참조 가져오기 및 변환 (수정) ---
    // 1. 먼저 모든 필요한 맵에 대한 MapRefMut 참조를 얻습니다.
    //    이 참조 자체는 ebpf 객체에 대한 가변 참조를 길게 유지하지 않습니다.
    let mut ip_id_map_ref_mut = ebpf // mut 추가
        .map_mut("IP_ID_MAP")
        .ok_or_else(|| anyhow!("Map 'IP_ID_MAP' not found"))?;
    let mut policy_l4_map_ref_mut = ebpf // mut 추가
        .map_mut("BLOCK_POLICY_L4_MAP")
        .ok_or_else(|| anyhow!("Map 'BLOCK_POLICY_L4_MAP' not found"))?;
    let mut policy_l3_map_ref_mut = ebpf // mut 추가
        .map_mut("BLOCK_POLICY_L3_MAP")
        .ok_or_else(|| anyhow!("Map 'BLOCK_POLICY_L3_MAP' not found"))?;

    // 이제 ebpf 객체는 더 이상 가변적으로 빌려지지 않았습니다.

    // 2. 얻은 MapRefMut 참조들을 사용하여 AyaHashMap<&mut MapData, ...> 타입으로 변환합니다.
    //    AyaHashMap::try_from은 MapRefMut에 대한 가변 참조를 인자로 받습니다.
    let mut ip_id_map: AyaHashMap<&mut MapData, u32, u32> = AyaHashMap::try_from(&mut ip_id_map_ref_mut)?;
    let mut policy_l4_map: AyaHashMap<&mut MapData, PolicyKeyL4, u32> = AyaHashMap::try_from(&mut policy_l4_map_ref_mut)?;
    let mut policy_l3_map: AyaHashMap<&mut MapData, PolicyKeyL3, u32> = AyaHashMap::try_from(&mut policy_l3_map_ref_mut)?;
    // --- 여기까지 수정 ---

    // 문제구간
    //

    let mut local_ip_to_id: StdHashMap<u32, u32> = StdHashMap::new();
    let mut next_id_counter: u32 = 1; // ID는 1부터 시작 (0은 WORLD_ID)

    async fn get_or_assign_id(
        ip_addr: u32, 
        local_map: &mut StdHashMap<u32, u32>,
        ebpf_map: &mut AyaHashMap<&mut MapData, u32, u32>,
        counter: &mut u32,
    ) -> anyhow::Result<u32> {
        if ip_addr == 0 {
            return Ok(WORLD_ID);
        }

        if let Some(id) = local_map.get(&ip_addr) {
            Ok(*id)
        } else {
            let new_id = *counter;
            *counter += 1;
            local_map.insert(ip_addr, new_id);
            // aya::maps::MapData는 Pod를 구현하지 않으므로 직접 키/값을 넣어야 함
            ebpf_map.insert(ip_addr, new_id, 0)
                    .map_err(|e| anyhow!("Failed to insert IP->ID mapping into eBPF map: {}", e))?;
            // {:i} 포맷터는 aya-log에서만 사용 가능, 여기서는 직접 변환 필요
            info!("Assigned ID {} to IP {}", new_id, Ipv4Addr::from(ip_addr));
            Ok(new_id)
        }
    }

    // --- 데이터베이스에서 L4 규칙 조회 및 삽입 ---
    info!("Fetching L4 block rules from the database...");
    let l4_rows = sqlx::query!(
        r#"
        SELECT src_addr, dst_addr, dst_port, protocol, action
        FROM block_policy_l4
        "# // 필요시 WHERE 조건 추가
    )
    .fetch_all(&pool)
    .await
    .context("Failed to fetch L4 rules from the database.")?;
    info!("{} L4 rules selected.", l4_rows.len());

    info!("Inserting L4 rules into eBPF map...");
    for row in l4_rows {
        // (BIGINT/INTEGER/SMALLINT -> u32/u16/u8)
        let src_addr_u32 = row.src_addr.unwrap_or(0) as u32;
        let dst_addr_u32 = row.dst_addr.unwrap_or(0) as u32;
        let dst_port_u16 = row.dst_port.unwrap_or(0) as u16; 
        let protocol_u8 = row.protocol.unwrap_or(0) as u8; 
        let db_action = row.action.unwrap_or(DB_ACTION_DROP);  

        // IP 주소에 대한 ID 가져오기 또는 할당
        let src_id = get_or_assign_id(src_addr_u32, &mut local_ip_to_id, &mut ip_id_map, &mut next_id_counter).await?;
        let dst_id = get_or_assign_id(dst_addr_u32, &mut local_ip_to_id, &mut ip_id_map, &mut next_id_counter).await?;

        // L4 정책 키 생성
        let key = PolicyKeyL4 {
            src_id,
            dst_id,
            dst_port: dst_port_u16, 
            protocol: protocol_u8,
            _padding: 0,
        };
        // 값 0은 '차단'을 의미한다고 가정
        let ebpf_action = if db_action == DB_ACTION_DROP { EBPF_ACTION_DROP } else { EBPF_ACTION_PASS };
        match policy_l4_map.insert(key, ebpf_action, 0) { 
            Ok(_) => { info!("Inserted L4 rule: {:?} -> Action: {}", key, ebpf_action); }
            Err(e) => warn!("L4 rule insert failed {:?}: {}", key, e),
        }
        match policy_l4_map.insert(key, 0u32, 0) {
            Ok(_) => { info!("Inserted L4 block rule: {:?}", key); }
            Err(e) => warn!("L4 rule insert failed {:?}: {}", key, e),
        }
    }
    info!("L4 rule insertion complete.");

    info!("Fetching L3 block rules from the database...");
    let l3_rows = sqlx::query!(
        r#"
        SELECT src_addr, dst_addr, action
        FROM block_policy_l3
        "# // 필요시 WHERE 조건 추가
    )
    .fetch_all(&pool)
    .await
    .context("Failed to fetch L3 rules from the database.")?;
    info!("{} L3 rules selected.", l3_rows.len());

    info!("Inserting L3 rules into eBPF map...");
    for row in l3_rows {
        // DB 값 가져오기 (BIGINT -> u32)
        let src_addr_u32 = row.src_addr.unwrap_or(0) as u32;
        let dst_addr_u32 = row.dst_addr.unwrap_or(0) as u32;
        let db_action = row.action.unwrap_or(DB_ACTION_DROP);

        // IP 주소에 대한 ID 가져오기 또는 할당
        let src_id = get_or_assign_id(src_addr_u32, &mut local_ip_to_id, &mut ip_id_map, &mut next_id_counter).await?;
        let dst_id = get_or_assign_id(dst_addr_u32, &mut local_ip_to_id, &mut ip_id_map, &mut next_id_counter).await?;

        // L3 정책 키 생성
        let key = PolicyKeyL3 { src_id, dst_id };
        let ebpf_action = if db_action == DB_ACTION_DROP { EBPF_ACTION_DROP } else { EBPF_ACTION_PASS };
        match policy_l3_map.insert(key, ebpf_action, 0) { 
            Ok(_) => { info!("Inserted L3 rule: {:?} -> Action: {}", key, ebpf_action); }
            Err(e) => warn!("L3 rule insert failed {:?}: {}", key, e),
        }
    }
    info!("L3 rule insertion complete.");

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
