// firewall-common/src/lib.rs
#![no_std]

// --- Packet ---
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct PacketInfo {
    pub src_addr: u32,       
    pub dst_addr: u32,      
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _reserved: [u8; 3],
}

// --- L3 ---
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct PolicyKeyL3 {
    pub src_id: u32,
    pub dst_id: u32,
}

// --- L4 ---
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct PolicyKeyL4 {
    pub src_id: u32,
    pub dst_id: u32,
    pub dst_port: u16, 
    pub protocol: u8,
    pub _padding: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketInfo {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKeyL4 {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKeyL3 {}
