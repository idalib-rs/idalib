use bitflags::bitflags;

use crate::ffi::typeinf::*;

bitflags! {
    /// Flags controlling how type declarations are extracted by [`IDB::format_decls`] and [`IDB::format_cfunc_decls`].
    ///
    /// These correspond to the `PDF_*` constants in the IDA SDK's `typeinf.hpp`.
    ///
    /// [`IDB::format_decls`]: crate::idb::IDB::format_decls
    /// [`IDB::format_cfunc_decls`]: crate::idb::IDB::format_cfunc_decls
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FormatDeclsOptions: u32 {
        /// Include all type dependencies.
        const INCL_DEPS = PDF_INCL_DEPS as _;
        /// Allow forward declarations.
        const DEF_FWD = PDF_DEF_FWD as _;
        /// Include base types: `__int8`, `__int16`, etc.
        const DEF_BASE = PDF_DEF_BASE as _;
        /// Prepend output with a descriptive comment.
        const HEADER_CMT = PDF_HEADER_CMT as _;
        /// Ignore types with anonymous names.
        const NO_ANON_NAME = PDF_NO_ANON_NAME as _;
    }
}
