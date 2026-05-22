use bitflags::bitflags;

bitflags! {
    /// Flags controlling how type declarations are printed by [`IDB::print_decls`].
    ///
    /// These correspond to the `PDF_*` constants in the IDA SDK's `typeinf.hpp`.
    ///
    /// [`IDB::print_decls`]: crate::idb::IDB::print_decls
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PrintDeclsFlags: u32 {
        /// Include all type dependencies.
        const INCL_DEPS    = 0x01;
        /// Allow forward declarations.
        const DEF_FWD      = 0x02;
        /// Include base types: `__int8`, `__int16`, etc.
        const DEF_BASE     = 0x04;
        /// Prepend output with a descriptive comment.
        const HEADER_CMT   = 0x08;
        /// Ignore types with anonymous names.
        const NO_ANON_NAME = 0x10;
    }
}
