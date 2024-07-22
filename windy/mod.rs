use core::arch::asm;
use gimli::{BaseAddresses, EndianSlice, LittleEndian, UnwindSection};
use mini_backtrace::Backtrace;
use x86::bits64::paging::PAGE_SIZE_ENTRIES;
use x86::current::registers::{rbp, rip, rsp};
use crate::common::debug::unwind::reader::{DataReader, Reader};
use crate::{arch, debug, trace};
use crate::arch::{Registers, UnwindContext};
use crate::boot::BOOTINFO;
use crate::common::debug::symbols::KERNEL_SYMBOLS;
use crate::common::debug::unwind::dwarf::{PrologInfo, RegisterLocation, RegisterSavedWhere};
use crate::common::debug::unwind::offset::Offset;
use crate::common::debug::unwind::context::{Context, Register};

mod dwarf;
mod eh_frame;
mod reader;
mod offset;
pub mod context;

macro_rules! extern_to_addr {
    ($name:ident) => {
        &$name as *const _ as usize
    };
}

extern "C" {
    static __executable_start: u8;
    static __eh_frame_hdr_start: u8;
    static __eh_frame_hdr_end: u8;
    static __eh_frame_start: u8;
    static __eh_frame_end: u8;
}

pub fn unwind() {
    let pc = rip() as usize;
    let rsp = rsp() as usize;
    let rbp = rbp() as usize;

    let eh_frame_hdr_addr = unsafe { extern_to_addr!(__eh_frame_hdr_start) };
    let eh_frame_hdr_end = unsafe { extern_to_addr!(__eh_frame_hdr_end) };
    debug!("eh_frame_hdr_addr: {:#x?}", eh_frame_hdr_addr);
    debug!("eh_frame_hdr_len: {:#x?}", eh_frame_hdr_end - eh_frame_hdr_addr);
    let eh_frame_hdr = eh_frame::EhFrameHdr::new(eh_frame_hdr_addr, eh_frame_hdr_end).unwrap();

    let mut base_addresses = BaseAddresses::default().set_eh_frame_hdr(eh_frame_hdr_addr as u64);
    let gimli_hdr = gimli::EhFrameHdr::new(unsafe { core::slice::from_raw_parts(eh_frame_hdr_addr as *const u8, eh_frame_hdr_end - eh_frame_hdr_addr) }, LittleEndian);
    let gimli_parsed_hdr = gimli_hdr.parse(&base_addresses, 8).unwrap();

    debug!("eh_frame_hdr: {:#x?}", eh_frame_hdr);
    let fde_addr = eh_frame_hdr.search_fde(pc);
    debug!("fde_addr: {:#x?}", fde_addr);
    let ptr = gimli_parsed_hdr.table().unwrap().lookup(pc as u64, &base_addresses).unwrap().pointer();
    debug!("real_ptr: {:#x?}", ptr);

    let entry = eh_frame::FdeEntry::new(fde_addr.unwrap(), unsafe { extern_to_addr!(__eh_frame_end) });
    let entry2 = eh_frame::FdeEntry::new(ptr as usize, unsafe { extern_to_addr!(__eh_frame_end) });
    debug!("pc: {:#x?}", pc);
    debug!("entry: {:#x?}", entry);
    debug!("entry2: {:#x?}", entry2);

    let prolog_info = entry.as_ref().unwrap().parse_instructions(pc).unwrap();
    let ra_register = prolog_info.saved_registers[16];
    debug!("{:#x?}", ra_register);

    let kernel_address = Offset::from(BOOTINFO.kernel_address + BOOTINFO.physics_mem_offset);
    let mapped_address = Offset::from(unsafe { extern_to_addr!(__executable_start) });
    debug!("mapped_address: 0x{:#x}, kernel_address: 0x{:#x}", mapped_address, kernel_address);

    let mut ra = 0;
    let cfa = get_cfa(&prolog_info).unwrap();

    for i in 0..=32 {
        if prolog_info.saved_registers[i].location != RegisterSavedWhere::RegisterUnused {
            if i == entry.as_ref().unwrap().get_cie().as_ref().unwrap().ra_register as usize {
                ra = get_saved_register(cfa, &prolog_info.saved_registers[i]).unwrap();
            }
        }
    }

    debug!("ra: {:#x?}", ra);

    let bt = Backtrace::<16>::capture();
    for frame in bt.frames {
        debug!("{:#x?}", frame);
    }
}

pub fn get_saved_register(cfa: usize, saved_reg: &RegisterLocation) -> Option<usize> {
    // TODO: Implement this
    // https://github.com/Amanieu/mini-backtrace/blob/6aff7c46416ae73ffd2ca9d1ffc5c1ce1baa40b4/llvm-libunwind/src/DwarfInstructions.hpp#L79
    match saved_reg.location {
        RegisterSavedWhere::RegisterInCFA => {
            let addr = (Offset::from(cfa) + Offset::from(saved_reg.value as isize)).as_usize();
            let value = unsafe { core::ptr::read_unaligned(addr as *const usize) };
            Some(value)
        }
        _ => None
    }
}

pub fn get_cfa(prolog: &PrologInfo) -> Option<usize> {
    // TODO: Implement this
    // TODO: https://github.com/llvm/llvm-project/blob/main/libunwind/src/DwarfInstructions.hpp#L65
    if (prolog.cfa_register != 0) {
        let cfa = Offset::from(Registers::try_from(prolog.cfa_register as usize).ok()?.get()? as usize);
        let offset = Offset::from(prolog.cfa_register_offset as isize);
        debug!("cfa: 0x{:#x}, offset: 0x{:#x}", cfa, offset);
        Some((cfa + offset).as_usize())
    } else {
        None
    }
}