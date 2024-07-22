use alloc::boxed::Box;
use core::cell::Cell;
use core::intrinsics::unreachable;
use core::mem::MaybeUninit;
use core::ops::{Add, AddAssign, Sub};
use log::LevelFilter::Off;
use crate::common::debug::unwind::offset::Offset;
use crate::common::debug::unwind::reader::{DataReader, Reader};
use crate::debug;

#[cfg(target_arch = "x86_64")]
macro_rules! highest_register { () => { 32 }; }

pub(crate) use highest_register;

#[macro_use]
macro_rules! generate_converter {
    (
        #[repr($repr:ident)]
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident = $value:expr),* $(,)*
        }
    ) => {
        #[repr($repr)]
        $(#[$meta])*
        $vis enum $name {
            $($variant = $value),*
        }

        impl TryFrom<$repr> for $name {
            type Error = $repr;

            fn try_from(v: $repr) -> Result<Self, Self::Error> {
                match v {
                    $( $value => Ok($name::$variant), )*
                    _ => Err(v),
                }
            }
        }

        paste::item! {
            impl $name {
                pub fn [<to_ $repr>] (&self) -> $repr {
                    unsafe { core::mem::transmute_copy(&self) }
                }
            }
        }
    };
}

generate_converter!(
    #[repr(u8)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    // From LSB-4.1.0
    pub enum DWARFExceptionHeaderEncoding {
        AbsolutePointer = 0x00,
        UnsignedLEB128Value = 0x01,
        Unsigned2BytesValue = 0x02,
        Unsigned4BytesValue = 0x03,
        Unsigned8BytesValue = 0x04,
        SignedLEB128Value = 0x09,
        Signed2BytesValue = 0x0A,
        Signed4BytesValue = 0x0B,
        Signed8BytesValue = 0x0C,
        RelateToProgramCounter = 0x10,
        RelateToBeginningOfText = 0x20,
        RelateToBeginningOfGotOrEhFrameHdr = 0x30,
        RelateToBeginningOfFunction = 0x40,
        AlignedToAddressUnitSizedBoundary = 0x50,
        Omit = 0xff
    }
);

generate_converter!(
    #[repr(u8)]
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    // From libunwind
    pub enum DWARFUnwindInstructions {
        Nop                 = 0x0,
        SetLoc             = 0x1,
        AdvanceLoc1        = 0x2,
        AdvanceLoc2        = 0x3,
        AdvanceLoc4        = 0x4,
        OffsetExtended     = 0x5,
        RestoreExtended    = 0x6,
        Undefined           = 0x7,
        SameValue          = 0x8,
        Register            = 0x9,
        RememberState      = 0xA,
        RestoreState       = 0xB,
        DefCfa             = 0xC,
        DefCfaRegister    = 0xD,
        DefCfaOffset      = 0xE,
        DefCfaExpression  = 0xF,
        Expression         = 0x10,
        OffsetExtendedSf = 0x11,
        DefCfaSf         = 0x12,
        DefCfaOffsetSf  = 0x13,
        ValOffset         = 0x14,
        ValOffsetSf      = 0x15,
        ValExpression     = 0x16,
        AdvanceLoc        = 0x40, // high 2 bits are 0x1, lower 6 bits are delta
        Offset             = 0x80, // high 2 bits are 0x2, lower 6 bits are register
        Restore            = 0xC0, // high 2 bits are 0x3, lower 6 bits are register

        // GNU extensions
        GnuWindowSave              = 0x2D,
        GnuArgsSize                = 0x2E,
        GnuNegativeOffsetExtended  = 0x2F,

        // AARCH64 extensions
        // NegateRaState      = 0x2D
    }
);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LEB128;

impl LEB128 {
    pub fn decode_uleb128(reader: &DataReader) -> Option<Offset> {
        let mut result: usize = 0;
        let mut data: u8 = 0;
        let mut exit_index: usize = 0;
        for i in 0..reader.len() {
            data = reader.read_u8()?;
            result = (((data & 0x7f) as usize) << (i * 7)) | result;
            if (data & 0x80) != 0x80 {
                exit_index = i;
                break;
            }
        }
        if exit_index == 4 && ((data & 0x7f) & 0xf0) != 0 {
            None
        } else {
            Some(Offset::from(result))
        }
    }

    pub fn decode_sleb128(reader: &DataReader) -> Option<Offset> {
        const MASK: [usize; 5] = [0xffffff80, 0xffffc000, 0xffe00000, 0xf0000000, 0];
        const BITMASK: [usize; 5] = [0x40, 0x40, 0x40, 0x40, 0x8];
        let mut result: usize = 0;
        let mut data: u8 = 0;
        let mut exit_index: usize = 0;
        for i in 0..reader.len() {
            data = reader.read_u8()?;
            result = (((data & 0x7f) as usize) << (i * 7)) | result;
            if (data & 0x80) != 0x80 {
                if (BITMASK[i] & ((data & 0x7f) as usize)) > 0 {
                    result |= MASK[i];
                }
                exit_index = i;
                break;
            }
        }
        if exit_index == 4 && ((data & 0x7f) & 0xf0) != 0 {
            None
        } else {
            Some(Offset::from(result as isize))
        }
    }
}

#[derive(Debug)]
pub struct DWARFEncodedValue {
    pub format: DWARFExceptionHeaderEncoding,
    pub application: DWARFExceptionHeaderEncoding,
}

impl DWARFEncodedValue {
    pub fn decode(&self, reader: &DataReader, base: usize) -> Option<Offset> {
        let base_offset = Offset::from(base);
        let mut result: Offset = Offset::default();
        let mut substract: bool = false;

        match self.format {
            DWARFExceptionHeaderEncoding::AbsolutePointer => {
                result = Offset::from(reader.read_u64()?);
            }
            DWARFExceptionHeaderEncoding::Signed8BytesValue => {
                let content = reader.read_u64()? as i64;
                result = Offset::from(content as isize);
            }
            DWARFExceptionHeaderEncoding::Unsigned8BytesValue => {
                result = Offset::from(reader.read_u64()?);
            }
            DWARFExceptionHeaderEncoding::Signed2BytesValue => {
                let content = reader.read_u16()? as i16;
                result = Offset::from(content as isize);
            }
            DWARFExceptionHeaderEncoding::Unsigned2BytesValue => {
                result = Offset::from(reader.read_u16()? as usize);
            }
            DWARFExceptionHeaderEncoding::Signed4BytesValue => {
                let content = reader.read_u32()? as i32;
                result = Offset::from(content as isize);
            }
            DWARFExceptionHeaderEncoding::Unsigned4BytesValue => {
                result = Offset::from(reader.read_u32()? as usize);
            }
            DWARFExceptionHeaderEncoding::UnsignedLEB128Value => {
                result = LEB128::decode_uleb128(reader)?;
            }
            DWARFExceptionHeaderEncoding::SignedLEB128Value => {
                result = LEB128::decode_sleb128(reader)?;
            }
            _ => return None,
        }

        match self.application {
            DWARFExceptionHeaderEncoding::AbsolutePointer => {}
            DWARFExceptionHeaderEncoding::RelateToProgramCounter => {
                if substract {
                    result = base_offset - result;
                } else {
                    result += base_offset;
                }
            }
            DWARFExceptionHeaderEncoding::RelateToBeginningOfText => return None,
            DWARFExceptionHeaderEncoding::RelateToBeginningOfGotOrEhFrameHdr => {
                if base == 0 {
                    return None;
                }
                if substract {
                    result = base_offset - result;
                } else {
                    result += base_offset;
                }
            }
            DWARFExceptionHeaderEncoding::RelateToBeginningOfFunction => return None,
            DWARFExceptionHeaderEncoding::AlignedToAddressUnitSizedBoundary => return None,
            _ => return None,
        }

        Some(result)
    }

    pub fn to_u8(&self) -> u8 {
        (self.format as u8) | (self.application as u8)
    }
}

impl TryFrom<u8> for DWARFEncodedValue {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let format = DWARFExceptionHeaderEncoding::try_from(value & 0x0f);
        let application = DWARFExceptionHeaderEncoding::try_from(value & 0x70);
        if format.is_ok() && application.is_ok() {
            Ok(Self {
                format: DWARFExceptionHeaderEncoding::try_from(value & 0x0f)?,
                application: DWARFExceptionHeaderEncoding::try_from(value & 0xf0)?,
            })
        } else {
            Err(value)
        }
    }
}

#[repr(u8)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum RegisterSavedWhere {
    #[default]
    RegisterUnused = 0x00,
    RegisterUndefined = 0x01,
    RegisterInCFA = 0x02,
    RegisterInCFADecrypted = 0x03,
    RegisterOffsetFromCFA = 0x04,
    RegisterInRegister = 0x05,
    RegisterAtExpression = 0x06,
    RegisterIsExpression = 0x07,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RegisterLocation {
    pub location: RegisterSavedWhere,
    pub initial_state_saved: bool,
    pub value: usize,
}

#[derive(Default, Clone, Copy)]
pub enum InitializeTime {
    Lazy,
    #[default]
    Normal,
}

#[derive(Debug, Copy, Clone)]
pub struct PrologInfo {
    pub cfa_register: u32,
    pub cfa_register_offset: i32,
    pub cfa_expression: i64,
    pub sp_extra_arg_size: u32,
    pub saved_registers: [RegisterLocation; highest_register!() + 1]
}

impl Default for PrologInfo {
    fn default() -> Self {
        Self {
            cfa_register: 0,
            cfa_register_offset: 0,
            cfa_expression: 0,
            sp_extra_arg_size: 0,
            saved_registers: [RegisterLocation::default(); highest_register!() + 1]
        }
    }
}

impl PrologInfo {
    pub fn check_save_register(&mut self, reg: usize, initial_state: &mut PrologInfo) {
        if !self.saved_registers[reg].initial_state_saved {
            initial_state.saved_registers[reg] = self.saved_registers[reg];
            self.saved_registers[reg].initial_state_saved = true;
        }
    }

    pub fn set_register(&mut self, reg: usize, new_location: RegisterSavedWhere, new_value: usize, initial_state: &mut PrologInfo) {
        self.check_save_register(reg, initial_state);
        self.saved_registers[reg].location = new_location;
        self.saved_registers[reg].value = new_value;
    }

    pub fn set_register_location(&mut self, reg: usize, new_location: RegisterSavedWhere, initial_state: &mut PrologInfo) {
        self.check_save_register(reg, initial_state);
        self.saved_registers[reg].location = new_location;
    }

    pub fn set_register_value(&mut self, reg: usize, new_value: usize, initial_state: &mut PrologInfo) {
        self.check_save_register(reg, initial_state);
        self.saved_registers[reg].value = new_value;
    }

    pub fn restore_register_to_initial_state(&mut self, reg: usize, initial_state: &PrologInfo) {
        if self.saved_registers[reg].initial_state_saved {
            self.saved_registers[reg] = initial_state.saved_registers[reg];
        }
    }
}

pub struct PrologInfoStackEntry<'a> {
    pub prolog_info: PrologInfo,
    pub next: Option<&'a Self>,
}

impl<'a> PrologInfoStackEntry<'a> {
    pub fn new(prolog_info: PrologInfo) -> Self {
        Self {
            prolog_info,
            next: None,
        }
    }
}

#[derive(Default)]
pub struct RememberStack<'a> {
    stack: Cell<Option<&'a PrologInfoStackEntry<'a>>>
}

impl<'a> RememberStack<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, prolog_info: PrologInfo) {
        let mut entry = Box::new(PrologInfoStackEntry::new(prolog_info));
        if let Some(top) = self.stack.get() {
            entry.next = Some(top);
        }
        self.stack.set(Some(Box::leak(entry)));
    }

    pub fn pop(&mut self) -> Option<Box<PrologInfo>> {
        let top = self.stack.get();
        if let Some(top) = top {
            self.stack.set(top.next);
            unsafe {
                Some(Box::from_raw(top as *const _ as *mut PrologInfo))
            }
        } else {
            None
        }
    }

    pub fn top(&self) -> Option<&PrologInfo> {
        self.stack.get().map(|top| &top.prolog_info)
    }
}

impl Drop for RememberStack<'_> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}