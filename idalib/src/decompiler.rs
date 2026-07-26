use std::marker::PhantomData;

use crate::ffi::hexrays::{
    cblock_iter, cblock_t, cfunc_t, cfuncptr_t, cinsn_t, idalib_hexrays_cblock_iter,
    idalib_hexrays_cblock_iter_next, idalib_hexrays_cblock_len, idalib_hexrays_cfunc_body,
    idalib_hexrays_cfunc_pseudocode, idalib_hexrays_cfuncptr_inner,
};
use crate::idb::IDB;

pub use crate::ffi::hexrays::{HexRaysError, HexRaysErrorCode};

pub struct CFunction<'a> {
    ptr: *mut cfunc_t,
    _obj: cxx::UniquePtr<cfuncptr_t>,
    _marker: PhantomData<&'a IDB>,
}

pub struct CBlock<'a> {
    ptr: *mut cblock_t,
    _marker: PhantomData<&'a ()>,
}

pub struct CBlockIter<'a> {
    it: cxx::UniquePtr<cblock_iter>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for CBlockIter<'a> {
    type Item = CInsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_cblock_iter_next(self.it.pin_mut()) };

        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }
}

pub struct CInsn<'a> {
    #[allow(unused)]
    ptr: *mut cinsn_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CFunction<'a> {
    pub(crate) fn new(obj: cxx::UniquePtr<cfuncptr_t>) -> Option<Self> {
        let ptr = unsafe { idalib_hexrays_cfuncptr_inner(obj.as_ref().expect("valid pointer")) };

        if ptr.is_null() {
            return None;
        }

        Some(Self {
            ptr,
            _obj: obj,
            _marker: PhantomData,
        })
    }

    pub fn pseudocode(&self) -> String {
        unsafe { idalib_hexrays_cfunc_pseudocode(self.ptr) }
    }

    pub(crate) fn as_ptr(&self) -> *mut cfunc_t {
        self.ptr
    }

    pub fn body(&self) -> CBlock<'_> {
        let ptr = unsafe { idalib_hexrays_cfunc_body(self.ptr) };

        CBlock {
            ptr,
            _marker: PhantomData,
        }
    }
}

impl<'a> CBlock<'a> {
    pub fn iter(&self) -> CBlockIter<'_> {
        CBlockIter {
            it: unsafe { idalib_hexrays_cblock_iter(self.ptr) },
            _marker: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        unsafe { idalib_hexrays_cblock_len(self.ptr) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
