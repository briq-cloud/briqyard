//! The sealed-image fixture: a static ELF the tests build themselves, so no host binary
//! (whose size, linking and multicall dispatch vary by distribution) stands in for it.
//! It copies `/proc/self/exe`, then its standard input, to its standard output.

use std::arch::global_asm;

const LOAD_ADDRESS: u64 = 0x40_0000;
const HEADERS: u64 = 64 + 56;

#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = 62;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = 183;

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".pushsection .rodata.briq_native_fixture,\"a\"",
    ".globl briq_native_fixture_start",
    ".globl briq_native_fixture_end",
    "briq_native_fixture_start:",
    "sub rsp, 4096",
    "mov eax, 2",
    "lea rdi, [rip + briq_native_fixture_path]",
    "xor esi, esi",
    "syscall",
    "test rax, rax",
    "js briq_native_fixture_fail",
    "mov r12, rax",
    "briq_native_fixture_copy:",
    "xor eax, eax",
    "mov rdi, r12",
    "mov rsi, rsp",
    "mov edx, 4096",
    "syscall",
    "test rax, rax",
    "js briq_native_fixture_fail",
    "jz briq_native_fixture_eof",
    "mov r13, rax",
    "mov r14, rsp",
    "briq_native_fixture_write:",
    "mov eax, 1",
    "mov edi, 1",
    "mov rsi, r14",
    "mov rdx, r13",
    "syscall",
    "test rax, rax",
    "jle briq_native_fixture_fail",
    "add r14, rax",
    "sub r13, rax",
    "jnz briq_native_fixture_write",
    "jmp briq_native_fixture_copy",
    "briq_native_fixture_eof:",
    "test r12, r12",
    "jz briq_native_fixture_done",
    "xor r12d, r12d",
    "jmp briq_native_fixture_copy",
    "briq_native_fixture_done:",
    "xor edi, edi",
    "mov eax, 60",
    "syscall",
    "briq_native_fixture_fail:",
    "mov edi, 1",
    "mov eax, 60",
    "syscall",
    "briq_native_fixture_path:",
    ".asciz \"/proc/self/exe\"",
    "briq_native_fixture_end:",
    ".popsection",
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    ".pushsection .rodata.briq_native_fixture,\"a\"",
    ".globl briq_native_fixture_start",
    ".globl briq_native_fixture_end",
    "briq_native_fixture_start:",
    "sub sp, sp, #4096",
    "mov x8, #56",
    "mov x0, #-100",
    "adr x1, briq_native_fixture_path",
    "mov x2, #0",
    "mov x3, #0",
    "svc #0",
    "cmp x0, #0",
    "b.lt briq_native_fixture_fail",
    "mov x19, x0",
    "briq_native_fixture_copy:",
    "mov x8, #63",
    "mov x0, x19",
    "mov x1, sp",
    "mov x2, #4096",
    "svc #0",
    "cmp x0, #0",
    "b.lt briq_native_fixture_fail",
    "b.eq briq_native_fixture_eof",
    "mov x20, x0",
    "mov x21, sp",
    "briq_native_fixture_write:",
    "mov x8, #64",
    "mov x0, #1",
    "mov x1, x21",
    "mov x2, x20",
    "svc #0",
    "cmp x0, #0",
    "b.le briq_native_fixture_fail",
    "add x21, x21, x0",
    "subs x20, x20, x0",
    "b.ne briq_native_fixture_write",
    "b briq_native_fixture_copy",
    "briq_native_fixture_eof:",
    "cbz x19, briq_native_fixture_done",
    "mov x19, #0",
    "b briq_native_fixture_copy",
    "briq_native_fixture_done:",
    "mov x0, #0",
    "mov x8, #93",
    "svc #0",
    "briq_native_fixture_fail:",
    "mov x0, #1",
    "mov x8, #93",
    "svc #0",
    "briq_native_fixture_path:",
    ".asciz \"/proc/self/exe\"",
    ".balign 4",
    "briq_native_fixture_end:",
    ".popsection",
);

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the sealed-image fixture has no program for this architecture");

extern "C" {
    static briq_native_fixture_start: u8;
    static briq_native_fixture_end: u8;
}

pub(super) fn native_image() -> Vec<u8> {
    let program = unsafe {
        let start = std::ptr::addr_of!(briq_native_fixture_start);
        let end = std::ptr::addr_of!(briq_native_fixture_end);
        std::slice::from_raw_parts(start, end as usize - start as usize)
    };
    let size = HEADERS + program.len() as u64;
    let mut image = Vec::with_capacity(size as usize);
    image.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    image.extend_from_slice(&2u16.to_le_bytes());
    image.extend_from_slice(&MACHINE.to_le_bytes());
    image.extend_from_slice(&1u32.to_le_bytes());
    image.extend_from_slice(&(LOAD_ADDRESS + HEADERS).to_le_bytes());
    image.extend_from_slice(&64u64.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes());
    for field in [64u16, 56, 1, 0, 0, 0] {
        image.extend_from_slice(&field.to_le_bytes());
    }
    image.extend_from_slice(&1u32.to_le_bytes());
    image.extend_from_slice(&5u32.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&LOAD_ADDRESS.to_le_bytes());
    image.extend_from_slice(&LOAD_ADDRESS.to_le_bytes());
    image.extend_from_slice(&size.to_le_bytes());
    image.extend_from_slice(&size.to_le_bytes());
    image.extend_from_slice(&0x1000u64.to_le_bytes());
    image.extend_from_slice(program);
    image
}
