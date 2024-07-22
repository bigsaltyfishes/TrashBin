# Windy
## What's this?
This is a `Unwinder`. A part of `Hirkari` Kernel.

## Current status
Well, pasre `.eh_frame_hdr`, `Common Information Entry`, `Frame Description Entry` and `Call Frame Instruction` only. Haven't fully tested yet, but as for now, it just works(Only tested on x86_64 platform).

## Why write this?
`gimili` is too hard to use for me. I need a more simple-to-use unwinder for get unwind info. (The most important reason is, while `gimli`'s UnwindContext instance created, an unknown exception will raise that kernel will crash, since interrupt handler cannot handle this exception, it is a hard work for me to debug this, as I'm new here.)

## What projects were referenced?
In general, this is just a Rust implementation of LLVM's `libunwind`.

## Why pending?
`Hikari` is a high-half designed kernel, using Limine Boot Protocol, it maps whole physical memory to high-half part of virtual address space. And of course kernel stack is allocated from there. But kernel is loaded at the high-half space of the high-half part of virtual address space. Kernel and Stack is in different address space. It's hard to recover registers from DWARF information since CFI is using stack addresses as base address to calculate CFA and other registers values. At least for now I don't know how to recover saved registeries. Since unwind via FP pointer is working properly, so pending this until I findout how to solve this.