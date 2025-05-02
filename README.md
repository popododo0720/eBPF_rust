# eBPF 이용한 패킷 분석

현재 인바운드만 제작완료

포트 미러링으로 테스트 - 연결할 인터페이스 Promiscuous Mode 활성화 필요
```
sudo ip link set enp11s0 promisc on
```

## Firewall Struct Table - inbound, outbound

| 필드명              | 데이터 타입  | 기본값          | 설명                       |
|-------------------|------------|---------------|--------------------------|
| `id`            | `SERIAL`   | `PRIMARY KEY` | 고유 ID 값                |
| `src_addr`      | `BIGINT`   | `0`           | 출발지 IP (u32, Little Endian)     |
| `dst_addr`      | `BIGINT`   | `0`           | 목적지 IP (u32, Little Endian)     |
| `src_port`      | `INTEGER`  | `0`           | 출발지 포트 (u32, Little Endian)          |
| `dst_port`      | `INTEGER`  | `0`           | 목적지 포트 (u32, Little Endian)          |
| `protocol`      | `INTEGER`  | `0`           | 프로토콜 정보              |
| `_reserved`     | `BYTEA`    | `'\x000000'`  | 예약된 필드 (바이트 배열)  |
| `src_addr_formatted` | `INET` | `'0.0.0.0'`   | 출발지 IP (포맷된 형식)   |
| `dst_addr_formatted` | `INET` | `'0.0.0.0'`   | 목적지 IP (포맷된 형식)   |
| `src_port_formatted` | `INTEGER` | `0`         | 포맷된 출발지 포트         |
| `dst_port_formatted` | `INTEGER` | `0`         | 포맷된 목적지 포트         |
---

## run
```
DATABASE_URL="postgres://id:passwd@ip:port/database" RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

## build
```
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

