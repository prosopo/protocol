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


// #[allow(unused_imports)] // do not remove StorageLayout, it is used in derives
// use ink::storage::{traits::StorageLayout};
//     /// The Prosopo error types
//     ///
    #[derive(
        Default, PartialEq, Debug, Eq, Clone, Copy, 
        // scale::Encode, scale::Decode, 
        PartialOrd, Ord,
    )]
//     #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
    pub enum Error {
        /// Returned if calling account is not authorised to perform action
        NotAuthorised,
        /// Returned when the contract to address transfer fails
        ContractTransferFailed,
        /// Returned if provider exists when it shouldn't
        ProviderExists,
        /// Returned if provider does not exist when it should
        ProviderDoesNotExist,
        /// Returned if provider has insufficient funds to operate
        ProviderInsufficientFunds,
        /// Returned if provider is inactive and trying to use the service
        ProviderInactive,
        /// Returned if url is already used by another provider
        ProviderUrlUsed,
        /// Returned if dapp exists when it shouldn't
        DappExists,
        /// Returned if dapp does not exist when it should
        DappDoesNotExist,
        /// Returned if dapp is inactive and trying to use the service
        DappInactive,
        /// Returned if dapp has insufficient funds to operate
        DappInsufficientFunds,
        /// Returned if captcha data does not exist
        CaptchaDataDoesNotExist,
        /// Returned if solution commitment does not exist when it should
        CommitDoesNotExist,
        /// Returned if dapp user does not exist when it should
        DappUserDoesNotExist,
        /// Returned if there are no active providers
        NoActiveProviders,
        /// Returned if the dataset ID and dataset ID with solutions are identical
        DatasetIdSolutionsSame,
        /// CodeNotFound ink env error
        CodeNotFound,
        /// An unknown ink env error has occurred
        #[default]
        Unknown,
        /// Invalid contract
        InvalidContract,
        /// Invalid payee. Returned when the payee value does not exist in the enum
        InvalidPayee,
        /// Returned if not all captcha statuses have been handled
        InvalidCaptchaStatus,
        /// No correct captchas in history (either history is empty or all captchas are incorrect)
        NoCorrectCaptcha,
        /// Returned if not enough providers are active
        NotEnoughActiveProviders,
        /// Returned if provider fee is too high
        ProviderFeeTooHigh,
        /// Returned if the commitment already exists
        CommitAlreadyExists,
        CaptchaSolutionCommitmentAlreadyExists,
        /// Returned if verification of a signature fails (could be for many reasons, e.g. invalid public key, invalid payload, invalid signature)
        VerifyFailed,
    }

/// An ink contract must be defined in order to import functions into another contract
#[ink::contract]
pub mod common {


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