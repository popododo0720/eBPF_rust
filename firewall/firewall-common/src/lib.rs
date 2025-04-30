// firewall-common/src/lib.rs
#![no_std]

use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Zeroable, Pod)]
pub struct FirewallStruct {
    pub src_addr: u32,       
    pub dst_addr: u32,      
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _reserved: [u8; 3],
}

