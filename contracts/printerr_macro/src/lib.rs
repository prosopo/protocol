#![cfg_attr(not(feature = "std"), no_std)]

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