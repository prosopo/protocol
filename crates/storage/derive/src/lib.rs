extern crate proc_macro;

mod enum_spread_allocate;

use self::enum_spread_allocate::enum_spread_allocate_derive;

synstructure::decl_derive!(
    [EnumSpreadAllocate] => enum_spread_allocate_derive
);
