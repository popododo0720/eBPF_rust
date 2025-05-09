// firewall-common/src/lib.rs
#![no_std]


#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct FirewallStruct {
    pub src_addr: u32,       
    pub dst_addr: u32,      
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _reserved: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallStruct {} // (1)
