use derivative::Derivative;
use x86::bits64::rflags::read;
use x86::task::tr;
use crate::common::debug::unwind::dwarf;
use crate::common::debug::unwind::dwarf::{DWARFEncodedValue, DWARFExceptionHeaderEncoding, DWARFUnwindInstructions, LEB128, PrologInfo, RegisterSavedWhere, RememberStack};
use crate::common::debug::unwind::offset::Offset;
use crate::common::debug::unwind::reader::{DataReader, Reader};
use crate::{debug, trace};

#[derive(Debug, Default)]
pub struct Augmentation {
    pub fde_have_augmentation_data: bool,
    pub personality_encoding: Option<DWARFEncodedValue>,
    pub personality_offset_in_cie: Option<u8>,
    pub personality: Option<usize>,
    pub lsda_encoding: Option<DWARFEncodedValue>,
    pub pointer_encoding: Option<DWARFEncodedValue>,
    pub is_signal_frame: bool,
    #[cfg(target_arch = "aarch64")]
    pub addresses_signed_with_B_key: bool,
    #[cfg(target_arch = "aarch64")]
    pub mte_tagged_frame: bool,
}

impl Augmentation {
    pub fn from_reader(augmentation_string: &str, reader: &DataReader, cie_start: usize) -> Option<Self> {
        let mut result = Self::default();
        let augmentation_string_chars = augmentation_string.chars();
        if augmentation_string.starts_with('z') {
            // Skip the length of the augmentation data
            let _ = LEB128::decode_uleb128(reader)?;
            for c in augmentation_string_chars {
                match c {
                    'z' => result.fde_have_augmentation_data = true,
                    'P' => {
                        result.personality_encoding = Some(DWARFEncodedValue::try_from(reader.read_u8()?).ok()?);
                        result.personality_offset_in_cie = Some((reader.as_ptr() as usize - cie_start) as u8);
                        result.personality = Some(result.personality_encoding.as_ref()?.decode(&reader, reader.as_ptr() as usize)?.as_usize());
                    },
                    'L' => {
                        result.lsda_encoding = Some(DWARFEncodedValue::try_from(reader.read_u8()?).ok()?);
                    },
                    'R' => {
                        result.pointer_encoding = Some(DWARFEncodedValue::try_from(reader.read_u8()?).ok()?);
                    },
                    'S' => {
                        result.is_signal_frame = true;
                    },
                    #[cfg(target_arch = "aarch64")]
                    'B' => {
                        result.addresses_signed_with_B_key = true;
                    },
                    #[cfg(target_arch = "aarch64")]
                    'G' => {
                        result.mte_tagged_frame = true;
                    }
                    _ => {}
                }
            }
            return Some(result);
        }
        None
    }
}

pub struct CieEntry {
    pub cie_id: u32,
    pub code_align_factor: u32,
    pub data_align_factor: i32,
    pub ra_register: u8,
    pub augmentation: Option<Augmentation>,
    pub initial_instructions: DataReader,
}

impl CieEntry {
    pub fn new(addr: usize, limit: usize) -> Option<Self> {
        let reader = DataReader::new(addr as *const u8, limit as *const u8);
        let mut length: usize = reader.read_u32()? as usize;
        if length == 0 {
            return None;
        } else if length == 0xffffffff {
            length = reader.read_u64()?;
        };

        // Reset limit of reader to the length of the CIE entry
        reader.reset_limit((reader.as_ptr() as usize + length) as *const u8);

        let cie_id = reader.read_u32()?;
        let version = reader.read_u8()?;
        assert_eq!(version, 1, "CIE version must be 1");
        assert_eq!(cie_id, 0, "CIE id must be 0");

        let augmentation_string_ptr: *const u8 = reader.as_ptr();
        let mut augmentation_string_len: usize = 0;
        while reader.read_u8()? != 0 {
            augmentation_string_len += 1;
        }

        let augmentation_string = if augmentation_string_len == 0 {
            None
        } else {
            Some(unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(augmentation_string_ptr, augmentation_string_len)) })
        };

        let code_align_factor = LEB128::decode_uleb128(&reader)?.as_usize() as u32;
        let data_align_factor = LEB128::decode_sleb128(&reader)?.as_isize() as i32;

        let ra_register = LEB128::decode_uleb128(&reader)?.as_usize();
        assert!(ra_register < 255, "ra_register must be less than 255");

        let augmentation = Augmentation::from_reader(augmentation_string?, &reader, addr);

        Some(Self {
            cie_id,
            code_align_factor,
            data_align_factor,
            ra_register: ra_register as u8,
            augmentation,
            initial_instructions: reader
        })
    }
}

pub struct ParsedFdeInstructions {
    data: DataReader,
}

impl ParsedFdeInstructions {
    pub fn new(cie: &CieEntry, fde: &FdeEntry, pc: usize, fde_pc_start: usize) -> Option<PrologInfo> {
        debug!("CIE: {:#x?}", cie.cie_id);
        let mut remember_stack = RememberStack::default();
        let readers = [&cie.initial_instructions, fde.call_frame_instruction.as_ref()?];
        let pc_offset = [Offset::from(Offset::from(-1isize).as_usize()), Offset::from(pc - fde_pc_start)];
        let mut results = PrologInfo::default();
        for i in 0..2 {
            debug!("READER: {:#x?}", i);
            let mut reader = readers[i].clone();
            let pc_offset = pc_offset[i];
            let mut code_offset: Offset = Offset::default();

            let mut initial_state = PrologInfo::default();
            while (reader.len() > 0) && (code_offset < pc_offset) {
                let mut reg = 0usize;
                let mut reg2 = 0usize;
                let mut offset = Offset::default();
                let mut length = 0usize;
                let opcode = reader.read_u8()?;
                let mut operand = 0u8;

                match DWARFUnwindInstructions::try_from(opcode) {
                    Ok(DWARFUnwindInstructions::Nop) => {}
                    Ok(DWARFUnwindInstructions::SetLoc) => {
                        code_offset = cie.augmentation.as_ref()?.pointer_encoding.as_ref()?.decode(&reader, reader.as_ptr() as usize)?;
                        trace!("SetLoc: {:#x}", code_offset);
                    }
                    Ok(DWARFUnwindInstructions::AdvanceLoc1) => {
                        code_offset += Offset::from(reader.read_u8()? as usize * cie.code_align_factor as usize);
                        trace!("AdvanceLoc1: {:#x}", code_offset);
                    }
                    Ok(DWARFUnwindInstructions::AdvanceLoc2) => {
                        code_offset += Offset::from(reader.read_u16()? as usize * cie.code_align_factor as usize);
                        trace!("AdvanceLoc2: {:#x}", code_offset);
                    }
                    Ok(DWARFUnwindInstructions::AdvanceLoc4) => {
                        code_offset += Offset::from(reader.read_u32()? as usize * cie.code_align_factor as usize);
                        trace!("AdvanceLoc4: {:#x}", code_offset);
                    }
                    Ok(DWARFUnwindInstructions::OffsetExtended) => {
                        // TODO: Use usize or isize?
                        // https://github.com/llvm/llvm-project/blob/main/libunwind/src/DwarfParser.hpp#L490
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        offset = LEB128::decode_sleb128(&reader)? * cie.data_align_factor as isize;
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.set_register(reg, RegisterSavedWhere::RegisterInCFA, offset.as_usize(), &mut initial_state);
                        trace!("OffsetExtended: reg: {:#x}, offset: {:#x}", reg, offset);
                    }
                    Ok(DWARFUnwindInstructions::RestoreExtended) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.restore_register_to_initial_state(reg, &mut initial_state);
                        trace!("RestoreExtended: reg: {:#x}", reg);
                    }
                    Ok(DWARFUnwindInstructions::Undefined) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.set_register_location(reg, RegisterSavedWhere::RegisterUndefined, &mut initial_state);
                        trace!("Undefined: reg: {:#x}", reg);
                    }
                    Ok(DWARFUnwindInstructions::SameValue) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.set_register_location(reg, RegisterSavedWhere::RegisterUnused, &mut initial_state);
                        trace!("SameValue: reg: {:#x}", reg);
                    }
                    Ok(DWARFUnwindInstructions::Register) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        reg2 = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() || reg2 > dwarf::highest_register!() {
                            return None;
                        }
                        results.set_register(reg, RegisterSavedWhere::RegisterInRegister, reg2, &mut initial_state);
                        trace!("Register: reg: {:#x}, reg2: {:#x}", reg, reg2);
                    }
                    Ok(DWARFUnwindInstructions::RememberState) => {
                        remember_stack.push(results);
                        trace!("RememberState");
                    }
                    Ok(DWARFUnwindInstructions::RestoreState) => {
                        if let Some(remembered_state) = remember_stack.pop() {
                            // TODO: Memory safe?
                            results = *remembered_state;
                        } else {
                            return None;
                        }
                        trace!("RestoreState");
                    }
                    Ok(DWARFUnwindInstructions::DefCfa) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        offset = LEB128::decode_sleb128(&reader)? * cie.data_align_factor as isize;
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.cfa_register = reg as u32;
                        results.cfa_register_offset = offset.as_isize() as i32;
                        trace!("DefCfa: reg: {}, offset: {}", reg, offset);
                    }
                    Ok(DWARFUnwindInstructions::DefCfaRegister) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.cfa_register = reg as u32;
                        trace!("DefCfaRegister: reg: {:#x}", reg);
                    }
                    Ok(DWARFUnwindInstructions::DefCfaOffset) => {
                        results.cfa_register_offset = LEB128::decode_sleb128(&reader)?.as_isize() as i32;
                        trace!("DefCfaOffset: offset: {:#x}", results.cfa_register_offset);
                    }
                    Ok(DWARFUnwindInstructions::DefCfaExpression) => {
                        results.cfa_register = 0;
                        results.cfa_expression = reader.as_ptr() as i64;
                        length = LEB128::decode_uleb128(&reader)?.as_usize();
                        assert!(length < i32::MAX as usize, "Pointer Overflow");
                        reader = reader.offset_forward(length)?;
                        trace!("DefCfaExpression: expression: {:x?}", results.cfa_expression);
                    }
                    Ok(DWARFUnwindInstructions::Expression) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.set_register(reg, RegisterSavedWhere::RegisterAtExpression, reader.as_ptr() as usize, &mut initial_state);
                        trace!("Expression: reg: {:x?}", reg);
                    }
                    Ok(DWARFUnwindInstructions::OffsetExtendedSf) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        offset = LEB128::decode_sleb128(&reader)? * cie.data_align_factor as isize;
                        results.set_register(reg, RegisterSavedWhere::RegisterInCFA, offset.as_usize(), &mut initial_state);
                        trace!("OffsetExtendedSf: reg: {:#x}, offset: {:#x}", reg, offset);
                    }
                    Ok(DWARFUnwindInstructions::DefCfaSf) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        offset = LEB128::decode_sleb128(&reader)? * cie.data_align_factor as isize;
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.cfa_register = reg as u32;
                        results.cfa_register_offset = offset.as_isize() as i32;
                        trace!("DefCfaSf: reg: {:#x}, offset: {:#x}", reg, offset);
                    }
                    Ok(DWARFUnwindInstructions::DefCfaOffsetSf) => {
                        results.cfa_register_offset = LEB128::decode_sleb128(&reader)?.as_isize() as i32;
                        trace!("DefCfaOffsetSf: offset: {:#x}", results.cfa_register_offset);
                    }
                    Ok(DWARFUnwindInstructions::ValOffset) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        offset = LEB128::decode_sleb128(&reader)? * cie.data_align_factor as isize;
                        results.set_register(reg, RegisterSavedWhere::RegisterOffsetFromCFA, offset.as_usize(), &mut initial_state);
                        trace!("ValOffset: reg: {:#x}, offset: {:#x}", reg, offset);
                    }
                    Ok(DWARFUnwindInstructions::ValOffsetSf) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        offset = LEB128::decode_sleb128(&reader)? * cie.data_align_factor as isize;
                        results.set_register(reg, RegisterSavedWhere::RegisterOffsetFromCFA, offset.as_usize(), &mut initial_state);
                        trace!("ValOffsetSf: reg: {:#x}, offset: {:#x}", reg, offset);
                    }
                    Ok(DWARFUnwindInstructions::ValExpression) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        results.set_register(reg, RegisterSavedWhere::RegisterIsExpression, reader.as_ptr() as usize, &mut initial_state);
                        length = LEB128::decode_uleb128(&reader)?.as_usize();
                        assert!(length < i32::MAX as usize, "Pointer Overflow");
                        reader = reader.offset_forward(length)?;
                        trace!("ValExpression: reg: {:x?}", reg);
                    }
                    Ok(DWARFUnwindInstructions::GnuArgsSize) => {
                        length = LEB128::decode_uleb128(&reader)?.as_usize();
                        results.sp_extra_arg_size = length as u32;
                        trace!("GnuArgsSize: size: {:#x}", length);
                    }
                    Ok(DWARFUnwindInstructions::GnuNegativeOffsetExtended) => {
                        reg = LEB128::decode_uleb128(&reader)?.as_usize();
                        if reg > dwarf::highest_register!() {
                            return None;
                        }
                        offset = LEB128::decode_sleb128(&reader)? * cie.data_align_factor as isize;
                        results.set_register(reg, RegisterSavedWhere::RegisterInCFA, offset.as_isize().wrapping_neg() as usize, &mut initial_state);
                        trace!("GnuNegativeOffsetExtended: reg: {:#x}, offset: {:#x}", reg, offset);
                    }
                    _ => {
                        operand = opcode & 0x3f;
                        match DWARFUnwindInstructions::try_from(opcode & 0xc0).ok()? {
                            DWARFUnwindInstructions::Offset => {
                                reg = operand as usize;
                                if reg > dwarf::highest_register!() {
                                    return None;
                                }
                                offset = LEB128::decode_uleb128(&reader)? * cie.data_align_factor as isize;
                                results.set_register(reg, RegisterSavedWhere::RegisterInCFA, offset.as_usize(), &mut initial_state);
                                trace!("Offset: reg: {:#x}, offset: {:#x}", reg, offset);
                            }
                            DWARFUnwindInstructions::AdvanceLoc => {
                                code_offset += Offset::from(operand as usize * cie.code_align_factor as usize);
                                trace!("AdvanceLoc: {:x}", code_offset);
                            }
                            DWARFUnwindInstructions::Restore => {
                                reg = operand as usize;
                                if reg > dwarf::highest_register!() {
                                    return None;
                                }
                                results.restore_register_to_initial_state(reg, &mut initial_state);
                                trace!("Restore: reg: {:#x}", reg);
                            }
                            _ => return None
                        }
                    }
                }
            }
            debug!("END OF LOOP! reader.len() == {:#x?}, code_offset == {:#x}, pc_offset == {:#x}", reader.len(), code_offset, pc_offset);
        }
        Some(results)
    }
}

#[derive(Debug, Default)]
pub struct FdeEntry {
    cie_pointer: usize,
    limit: usize,
    pc_start: usize,
    pc_range: usize,
    lsda: usize,
    call_frame_instruction: Option<DataReader>,
}

impl FdeEntry {
    pub fn new(addr: usize, limit: usize) -> Option<Self> {
        let mut result = Self::default();
        result.limit = limit;
        let mut reader = DataReader::new(addr as *const u8, limit as *const u8);
        let mut length: usize = reader.read_u32()? as usize;
        if length == 0 {
            return None;
        } else if length == 0xffffffff {
            length = reader.read_u64()?;
        };
        reader.reset_limit((reader.as_ptr() as usize + length) as *const u8);

        result.cie_pointer = reader.as_ptr() as usize - reader.read_u32()? as usize;
        let cie = CieEntry::new(result.cie_pointer, limit)?;

        let pointer_encoding = cie.augmentation.as_ref()?.pointer_encoding.as_ref()?;
        result.pc_start = pointer_encoding.decode(&reader, reader.as_ptr() as usize)?.as_usize();
        result.pc_range = DWARFEncodedValue::try_from(pointer_encoding.to_u8() & 0x0f).ok()?.decode(&reader, reader.as_ptr() as usize)?.as_usize();

        if cie.augmentation.as_ref()?.fde_have_augmentation_data {
            let augmentation_reader = reader.clone();
            let augmentation_data_len = LEB128::decode_uleb128(&augmentation_reader)?.as_usize();
            if let Some(lsda_encoding) = cie.augmentation.as_ref()?.lsda_encoding.as_ref() {
                if lsda_encoding.format != DWARFExceptionHeaderEncoding::Omit {
                    let stage1_encoding = DWARFEncodedValue::try_from(lsda_encoding.to_u8() & 0x0f).ok()?;
                    if stage1_encoding.decode(&augmentation_reader.clone(), augmentation_reader.as_ptr() as usize)?.as_usize() != 0 {
                        result.lsda = lsda_encoding.decode(&augmentation_reader, augmentation_reader.as_ptr() as usize)?.as_usize();
                    }
                }
            }
            // Skip the augmentation data
            reader = reader.offset_forward(augmentation_data_len)?;
        }
        result.call_frame_instruction = Some(reader);
        Some(result)
    }

    pub fn get_cie(&self) -> Option<CieEntry> {
        CieEntry::new(self.cie_pointer, self.limit)
    }

    pub fn parse_instructions(&self, pc: usize) -> Option<PrologInfo> {
        ParsedFdeInstructions::new(&self.get_cie()?, self, pc, self.pc_start)
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct FdeSearchEntry {
    pub initial_location: usize,
    pub address: usize,
}

impl FdeSearchEntry {
    pub fn parse(table: &DataReader, table_enc: &DWARFEncodedValue, base: usize) -> Option<Self> {
        let initial_location = table_enc.decode(table, base)?.as_usize();
        let address = table_enc.decode(table, base)?.as_usize();

        Some(Self {
            initial_location,
            address,
        })
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct EhFrameHdr {
    base: usize,
    eh_frame_ptr_enc: DWARFEncodedValue,
    fde_count_enc: DWARFEncodedValue,
    table_enc: DWARFEncodedValue,
    eh_frame_ptr: usize,
    fde_count: usize,
    table: Option<DataReader>,
}

impl EhFrameHdr {
    pub fn new(start: usize, end: usize) -> Option<Self> {
        let reader = DataReader::new(start as *const u8, end as *const u8);
        let version = reader.read_u8()?;
        assert_eq!(version, 1);
        let eh_frame_ptr_enc = DWARFEncodedValue::try_from(reader.read_u8()?).ok()?;
        let fde_count_enc = DWARFEncodedValue::try_from(reader.read_u8()?).ok()?;
        let table_enc = DWARFEncodedValue::try_from(reader.read_u8()?).ok()?;

        let eh_frame_ptr = eh_frame_ptr_enc.decode(&reader, reader.as_ptr() as usize)?.as_usize();
        let fde_count = fde_count_enc.decode(&reader, reader.as_ptr() as usize)?.as_usize();
        let table = if fde_count_enc.format == DWARFExceptionHeaderEncoding::Omit || fde_count_enc.application == DWARFExceptionHeaderEncoding::Omit {
            None
        } else {
            Some(reader)
        };

        Some(Self {
            base: start,
            eh_frame_ptr_enc,
            fde_count_enc,
            table_enc,
            eh_frame_ptr,
            fde_count,
            table,
        })
    }

    pub fn eh_frame_address(&self) -> usize {
        self.eh_frame_ptr
    }

    pub fn table_entry_size(&self) -> Option<usize> {
        match self.table_enc.format {
            DWARFExceptionHeaderEncoding::Signed2BytesValue |
            DWARFExceptionHeaderEncoding::Unsigned2BytesValue => Some(4),
            DWARFExceptionHeaderEncoding::Signed4BytesValue |
            DWARFExceptionHeaderEncoding::Unsigned4BytesValue => Some(8),
            DWARFExceptionHeaderEncoding::Signed8BytesValue |
            DWARFExceptionHeaderEncoding::Unsigned8BytesValue => Some(16),
            DWARFExceptionHeaderEncoding::SignedLEB128Value |
            DWARFExceptionHeaderEncoding::UnsignedLEB128Value => None,
            DWARFExceptionHeaderEncoding::Omit => None,
            _ => None
        }
    }

    pub fn search_fde(&self, pc: usize) -> Option<usize> {
        if let (Some(ent_size), Some(table)) = (self.table_entry_size(), self.table.as_ref()) {
            let mut low = 0;
            let mut pos = self.fde_count;
            while pos > 1 {
                let mid = low + (pos / 2);
                let reader = table.offset_forward(mid * ent_size)?;
                let entry = FdeSearchEntry::parse(&reader, &self.table_enc, self.base)?;
                if entry.initial_location == pc {
                    low = mid;
                    break;
                } else if entry.initial_location < pc {
                    low = mid;
                    pos -= (pos / 2);
                } else {
                    pos /= 2;
                }
            }

            let reader = table.offset_forward(low * ent_size)?;
            let entry = FdeSearchEntry::parse(&reader, &self.table_enc, self.base)?;
            Some(entry.address)
        } else {
            None
        }
    }
}