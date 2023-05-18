#![cfg_attr(not(feature = "std"), no_std)]

/// Print and return an error in ink
#[macro_export]
macro_rules! err {
    ($e:expr) => {{
        let self_ = get_self!();
        ink::env::debug_println!(
            "'{:?}' error in {:?}() at block {:?} with caller {:?}",
            $e,
            function_name!(),
            self_.env().block_number(),
            self_.env().caller(),
        );
        Err($e)
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
pub mod common {

    /// No fields are stored in the util contract as it's just filler
    #[ink(storage)]
    pub struct Common {}

    /// Implementation of the contract
    impl Common {
        #[ink(constructor)]
        pub fn noop_ctor() -> Self {
            Self {}
        }

        /// No-op function to fill the mandatory ink message requirement
        #[ink(message)]
        pub fn noop_func(&self) {}
    }

/// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// ************** READ BEFORE TESTING *******************
    /// The below code is technically just normal Rust code.
    /// Therefore you can use println!() as usual, but by default stdout is only shown for tests which fail.
    /// Run the tests via `cargo test` (no need for `cargo contract`!)
    /// *********************************
    #[cfg(test)]
    #[cfg_attr(
        debug_assertions,
        allow(
            dead_code,
            unused_imports,
            unused_variables,
            unused_mut,
            unused_must_use,
            non_upper_case_globals,
            non_shorthand_field_patterns
        )
    )]
    pub mod tests {

        
        use ink;
        use ink::env::AccountId;
        use ink::codegen::Env;
        use ink::env::hash::Blake2x256;
        use ink::env::hash::CryptoHash;
        use ink::env::hash::HashOutput;

        const set_caller: fn(AccountId) =
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>;
        const get_account_balance: fn(AccountId) -> Result<u128, ink::env::Error> =
            ink::env::test::get_account_balance::<ink::env::DefaultEnvironment>;
        const set_account_balance: fn(AccountId, u128) =
            ink::env::test::set_account_balance::<ink::env::DefaultEnvironment>;
        const set_callee: fn(AccountId) =
            ink::env::test::set_callee::<ink::env::DefaultEnvironment>;
        const default_accounts: fn() -> ink::env::test::DefaultAccounts<
            ink::env::DefaultEnvironment,
        > = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>;

        const ADMIN_ACCOUNT_PREFIX: u8 = 0x01;
        const DAPP_ACCOUNT_PREFIX: u8 = 0x02;
        const PROVIDER_ACCOUNT_PREFIX: u8 = 0x03;
        const USER_ACCOUNT_PREFIX: u8 = 0x04;
        const CONTRACT_ACCOUNT_PREFIX: u8 = 0x05;
        const CODE_HASH_PREFIX: u8 = 0x06;

            // unused account is 0x00 - do not use this, it will be the default caller, so could get around caller checks accidentally
            fn get_unused_account() -> AccountId {
                AccountId::from([0x00; 32])
            }

            // build an account. Accounts have the first byte set to the type of account and the next 16 bytes are the index of the account
            fn get_account_bytes(account_type: u8, index: u128) -> [u8; 32] {
                let mut bytes = [0x00; 32];
                bytes[0] = account_type;
                bytes[1..17].copy_from_slice(&index.to_le_bytes());
                bytes
            }

            fn get_account(account_type: u8, index: u128) -> AccountId {
                let account = AccountId::from(get_account_bytes(account_type, index));
                // fund the account so it exists if not already
                let balance = get_account_balance(account);
                if balance.is_err() {
                    // account doesn't have the existential deposit so doesn't exist
                    // give it funds to create it
                    set_account_balance(account, 1);
                }
                account
            }

            /// get the nth admin account. This ensures against account collisions, e.g. 1 account being both a provider and an admin, which can obviously cause issues with caller guards / permissions in the contract.
            fn get_admin_account(index: u128) -> AccountId {
                get_account(ADMIN_ACCOUNT_PREFIX, index)
            }

            /// get the nth provider account. This ensures against account collisions, e.g. 1 account being both a provider and an admin, which can obviously cause issues with caller guards / permissions in the contract.
            fn get_provider_account(index: u128) -> AccountId {
                get_account(PROVIDER_ACCOUNT_PREFIX, index)
            }

            /// get the nth dapp account. This ensures against account collisions, e.g. 1 account being both a provider and an admin, which can obviously cause issues with caller guards / permissions in the contract.
            fn get_dapp_account(index: u128) -> AccountId {
                get_account(DAPP_ACCOUNT_PREFIX, index)
            }

            /// get the nth user account. This ensures against account collisions, e.g. 1 account being both a provider and an admin, which can obviously cause issues with caller guards / permissions in the contract.
            fn get_user_account(index: u128) -> AccountId {
                get_account(USER_ACCOUNT_PREFIX, index)
            }

            /// get the nth contract account. This ensures against account collisions, e.g. 1 account being both a provider and an admin, which can obviously cause issues with caller guards / permissions in the contract.
            fn get_contract_account(index: u128) -> AccountId {
                get_account(CONTRACT_ACCOUNT_PREFIX, index)
            }

            /// get the nth code hash. This ensures against account collisions, e.g. 1 account being both a provider and an admin, which can obviously cause issues with caller guards / permissions in the contract.
            fn get_code_hash(index: u128) -> [u8; 32] {
                get_account_bytes(CODE_HASH_PREFIX, index)
            }

            /// get the nth contract. This ensures against account collisions, e.g. 1 account being both a provider and an admin, which can obviously cause issues with caller guards / permissions in the contract.
            fn get_contract(index: u128) -> Prosopo {
                let account = get_account(CONTRACT_ACCOUNT_PREFIX, index); // the account for the contract
                                                                           // make sure the contract gets allocated the above account
                set_callee(account);
                // give the contract account some funds
                set_account_balance(account, 1);
                // set the caller to the first admin
                set_caller(get_admin_account(0));
                // now construct the contract instance
                let mut contract =
                    Prosopo::new_unguarded(STAKE_THRESHOLD, STAKE_THRESHOLD, 10, 1000000, 0, 1000);
                // set the caller back to the unused acc
                set_caller(get_unused_account());
                // check the contract was created with the correct account
                assert_eq!(contract.env().account_id(), account);
                contract
            }
    }
}
