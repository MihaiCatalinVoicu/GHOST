//! The `.note.gnu.build-id` reader of `ghost-verify` (monitor rule (e), design §5.3): the GNU
//! build-id of a stripped library and of its split-debug file must be equal, so a symbol file
//! can be tied to the binary it describes. Hand-rolled over the ELF section table — the
//! verifier takes no object-code dependency (§9.1's public tree is source-only).
//!
//! Only 64-bit little-endian ELF is read: every GHOST library and symbol file is built for
//! Android ABIs or x86_64 Linux (§6.1), and a 32-bit or big-endian file is refused, not guessed.
//! The note is found by name (`.note.gnu.build-id`, an SHT_NOTE section) — both the linked
//! library and the `llvm-objcopy --only-keep-debug` split carry the section (§6.3's symbol
//! split keeps the note; measured on the shipped split outputs).

/// Why a file's build-id could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildIdError {
    /// Shorter than an ELF64 header, or not the `\x7fELF` magic.
    TooSmall,
    /// Not the 64-bit little-endian class the release files use.
    NotElf64Le,
    /// A header field is out of the file's bounds.
    Bounds,
    /// The section string table or the `.note.gnu.build-id` section is absent.
    NoSection,
    /// The section holds no well-formed `GNU` note of type 3 (NT_GNU_BUILD_ID).
    NoNote,
}

const ELF_HDR: usize = 64;
const SHENT: usize = 64;

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("8 bytes"))
}

/// The bytes of the file's GNU build-id note (20 bytes for the SHA-1 id §6.3 links with).
pub fn gnu_build_id(elf: &[u8]) -> Result<Vec<u8>, BuildIdError> {
    if elf.len() < ELF_HDR {
        return Err(BuildIdError::TooSmall);
    }
    if &elf[..4] != b"\x7fELF" {
        return Err(BuildIdError::TooSmall);
    }
    if elf[4] != 2 || elf[5] != 1 {
        return Err(BuildIdError::NotElf64Le); // EI_CLASS 64-bit, EI_DATA little-endian
    }
    let shoff = le64(&elf[0x28..0x30]) as usize;
    let shentsize = le16(&elf[0x3a..0x3c]) as usize;
    let shnum = le16(&elf[0x3c..0x3e]) as usize;
    let shstrndx = le16(&elf[0x3e..0x40]) as usize;
    if shentsize < SHENT || shnum == 0 || shstrndx >= shnum {
        return Err(BuildIdError::Bounds);
    }
    let table_end = shoff
        .checked_add(shentsize.checked_mul(shnum).ok_or(BuildIdError::Bounds)?)
        .ok_or(BuildIdError::Bounds)?;
    if table_end > elf.len() {
        return Err(BuildIdError::Bounds);
    }
    let section =
        |i: usize| -> &[u8] { &elf[shoff + i * shentsize..shoff + i * shentsize + SHENT] };
    // The section header string table (its own section's offset and size).
    let str_sh = section(shstrndx);
    let str_off = le64(&str_sh[0x18..0x20]) as usize;
    let str_size = le64(&str_sh[0x20..0x28]) as usize;
    if str_off.checked_add(str_size).ok_or(BuildIdError::Bounds)? > elf.len() {
        return Err(BuildIdError::Bounds);
    }
    let strtab = &elf[str_off..str_off + str_size];
    let name_at = |sh: &[u8]| -> Option<&str> {
        let noff = le32(&sh[0..4]) as usize;
        let end = strtab.get(noff..)?.iter().position(|&b| b == 0)? + noff;
        std::str::from_utf8(&strtab[noff..end]).ok()
    };
    for i in 0..shnum {
        let sh = section(i);
        if name_at(sh) != Some(".note.gnu.build-id") {
            continue;
        }
        if le32(&sh[4..8]) != 7 {
            return Err(BuildIdError::NoSection); // named like the note but not SHT_NOTE
        }
        let off = le64(&sh[0x18..0x20]) as usize;
        let size = le64(&sh[0x20..0x28]) as usize;
        if off.checked_add(size).ok_or(BuildIdError::Bounds)? > elf.len() {
            return Err(BuildIdError::Bounds);
        }
        return note_build_id(&elf[off..off + size]);
    }
    Err(BuildIdError::NoSection)
}

/// Walk one SHT_NOTE section for the `GNU`/NT_GNU_BUILD_ID note (RFC-style name padding to 4).
fn note_build_id(notes: &[u8]) -> Result<Vec<u8>, BuildIdError> {
    let mut pos = 0usize;
    while pos + 12 <= notes.len() {
        let namesz = le32(&notes[pos..pos + 4]) as usize;
        let descsz = le32(&notes[pos + 4..pos + 8]) as usize;
        let ty = le32(&notes[pos + 8..pos + 12]);
        let name_start = pos + 12;
        let name_end = name_start.checked_add(namesz).ok_or(BuildIdError::Bounds)?;
        let desc_start = name_end
            .checked_add((4 - namesz % 4) % 4)
            .ok_or(BuildIdError::Bounds)?;
        let desc_end = desc_start.checked_add(descsz).ok_or(BuildIdError::Bounds)?;
        if desc_end > notes.len() {
            return Err(BuildIdError::Bounds);
        }
        if ty == 3 && namesz == 4 && &notes[name_start..name_end] == b"GNU\0" {
            return Ok(notes[desc_start..desc_end].to_vec());
        }
        pos = desc_start + ((4 - descsz % 4) % 4);
    }
    Err(BuildIdError::NoNote)
}
