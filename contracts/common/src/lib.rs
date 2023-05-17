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

#[macro_export]
macro_rules! lazy {
    ($lazy:expr, $func:ident, $value:expr) => {
        let mut contents = $lazy.get_or_default();
        contents.$func($value);
        $lazy.set(&contents);
    };
}

/// An ink contract must be defined in order to import functions into another contract
#[ink::contract]
pub mod util {

    /// No fields are stored in the util contract as it's just filler
    #[ink(storage)]
    pub struct Util {}

    /// Implementation of the contract
    impl Util {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        /// No-op function to fill the mandatory ink message requirement
        #[ink(message)]
        pub fn noop(&self) {}
    }

}