use std::marker::PhantomData;

use bitflags::bitflags;

use crate::ffi::plugin::*;
use crate::idb::IDB;

pub use crate::ffi::processor::ids as id;

#[cfg(feature = "plugin")]
mod plugmod;
#[cfg(feature = "plugin")]
pub use plugmod::*;


bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PluginFlags: u64 {
        const MOD = flags::PLUGIN_MOD as u64;
        const DRAW = flags::PLUGIN_DRAW as u64;
        const SEG = flags::PLUGIN_SEG as u64;
        const UNL = flags::PLUGIN_UNL as u64;
        const HIDE = flags::PLUGIN_HIDE as u64;
        const DBG = flags::PLUGIN_DBG as u64;
        const PROC = flags::PLUGIN_PROC as u64;
        const FIX = flags::PLUGIN_FIX as u64;
        const MULTI = flags::PLUGIN_MULTI as u64;
        const SCRIPTED = flags::PLUGIN_SCRIPTED as u64;
    }
}

pub struct Plugin<'a> {
    ptr: *const plugin_t,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Plugin<'a> {
    pub(crate) fn from_ptr(ptr: *const plugin_t) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn run(&self, arg: usize) -> bool {
        unsafe { run_plugin(self.ptr, arg) }
    }

    pub fn version(&self) -> u64 {
        unsafe { idalib_plugin_version(self.ptr) }
    }

    pub fn flags(&self) -> PluginFlags {
        let bits = unsafe { idalib_plugin_flags(self.ptr) };
        PluginFlags::from_bits_retain(bits)
    }
}
