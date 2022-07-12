//! Building this module successfully guarantees that the catnip library is no-std compatible
//! and that it produces no panic branches (panic-never compatible)

#![no_std]
#![no_main]

#[allow(unused_imports)]
use catnip;

#[no_mangle]
pub fn _start() -> ! {
    loop {}
}
