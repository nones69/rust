#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![allow(dead_code)]

mod drivers;
mod arch;

use core::panic::PanicInfo;
use drivers::vga::{Color, ColorCode, Writer};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write;
    use drivers::serial::SERIAL1;
    let _ = writeln!(SERIAL1.lock(), "\n[KERNEL PANIC]\n{}", info);
    cpu_halt();
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut writer = Writer::new(ColorCode::new(Color::White, Color::Black));
    writer.clear_screen();

    writer.write_string("╔══════════════════════════════════════╗\n");
    writer.write_string("║      All-In-One ISO Build System     ║\n");
    writer.write_string("║      Hello from Rust OS!             ║\n");
    writer.write_string("║      x86_64 Bare-Metal Kernel v0.1   ║\n");
    writer.write_string("╚══════════════════════════════════════╝\n\n");
    writer.write_string("Kernel initialised successfully.\n");
    writer.write_string("Entering CPU halt loop — no scheduler loaded.\n");

    drivers::serial::init();
    arch::x86_64::interrupts::init_idt();

    cpu_halt()
}

#[inline(always)]
fn cpu_halt() -> ! {
    loop {
        x86_64::instructions::interrupts::enable_and_hlt();
    }
}