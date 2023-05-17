#![cfg_attr(not(feature = "std"), no_std)]

/// Print and return an error in ink
#[macro_export]
macro_rules! err {
    ($err:expr) => {{
        Err(get_self!().print_err($err, function_name!()))
    }};
}

#[macro_export]
macro_rules! err_fn {
    ($err:expr) => {
        || get_self!().print_err($err, function_name!())
    };
}

#[ink::contract]
pub mod abc {

    #[ink(storage)]
    pub struct Abc {}

    impl Abc {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        #[ink(message)]
        pub fn abc(&self, a: u8) -> u8 {
            a + 1
        }
    }

    pub fn def(a: u8) -> u8 {
        1 + a
    }

}