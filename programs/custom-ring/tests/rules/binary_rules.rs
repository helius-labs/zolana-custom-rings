//! The ring stack's SBF binaries hold no data relocation with a nonzero low word.

use solana_sbpf::elf_parser::{consts::R_X86_64_RELATIVE, Elf64};

use crate::common::deployed;

#[test]
fn every_data_pointer_keeps_its_addend_through_the_loader() {
    for program in ["custom_ring_program.so", "storage_program.so"] {
        let bytes = deployed(program);
        let elf = Elf64::parse(&bytes).expect("parse the SBF binary");
        let text = elf
            .section_header_table()
            .iter()
            .find(|header| elf.section_name(header.sh_name) == Ok(b".text".as_slice()))
            .and_then(|header| header.file_range())
            .expect("a text section");
        // The loader reads only the high word of a data slot.
        let dropped: Vec<usize> = elf
            .dynamic_relocations_table()
            .unwrap_or_default()
            .iter()
            .filter(|relocation| relocation.r_type() == R_X86_64_RELATIVE)
            .map(|relocation| relocation.r_offset as usize)
            .filter(|offset| !text.contains(offset))
            .filter(|offset| bytes.get(*offset..*offset + 4) != Some(&[0; 4]))
            .collect();
        assert!(
            dropped.is_empty(),
            "{program} loses the addend of the data pointers at {dropped:#x?}"
        );
    }
}
