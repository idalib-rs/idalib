use std::marker::PhantomData;
use std::mem;

use bitflags::bitflags;

use crate::ffi::xref::cref_t::*;
use crate::ffi::xref::dref_t::*;
use crate::ffi::xref::*;

use crate::idb::IDB;
use crate::Address;

pub struct XRef<'a> {
    inner: xrefblk_t,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Clone for XRef<'a> {
    fn clone(&self) -> Self {
        Self {
            inner: xrefblk_t {
                from: self.inner.from,
                to: self.inner.to,
                iscode: self.inner.iscode,
                type_: self.inner.type_,
                user: self.inner.user,
                _flags: self.inner._flags,
            },
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub enum XRefType {
    Code(CodeRef),
    Data(DataRef),
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[repr(u8)]
pub enum CodeRef {
    Unknown = fl_U as _,
    FarCall = fl_CF as _,
    NearCall = fl_CN as _,
    FarJump = fl_JF as _,
    NearJump = fl_JN as _,
    Obsolete = fl_USobsolete as _,
    Flow = fl_F as _,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
#[repr(u8)]
pub enum DataRef {
    Unknown = dr_U as _,
    Offset = dr_O as _,
    Write = dr_W as _,
    Read = dr_R as _,
    Text = dr_T as _,
    Informational = dr_I as _,
    EnumMember = dr_S as _,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
    pub struct XRefFlags: u8 {
        const USER = XREF_USER as _;
        const TAIL = XREF_TAIL as _;
        const BASE = XREF_BASE as _;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Hash)]
    pub struct XRefQuery: i32 {
        const ALL = XREF_ALL as _;
        const FAR = XREF_FAR as _;
        const DATA = XREF_DATA as _;
    }
}

impl<'a> XRef<'a> {
    pub(crate) fn from_repr(inner: xrefblk_t) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    pub fn from(&self) -> Address {
        self.inner.from.into()
    }

    pub fn to(&self) -> Address {
        self.inner.to.into()
    }

    pub fn flags(&self) -> XRefFlags {
        let flags = self.inner.type_ & !(XREF_MASK as u8);
        XRefFlags::from_bits_retain(flags)
    }

    pub fn type_(&self) -> XRefType {
        let type_ = self.inner.type_ & (XREF_MASK as u8);

        if self.is_code() {
            XRefType::Code(unsafe { mem::transmute::<u8, CodeRef>(type_) })
        } else {
            XRefType::Data(unsafe { mem::transmute::<u8, DataRef>(type_) })
        }
    }

    pub fn is_code(&self) -> bool {
        self.inner.iscode
    }

    pub fn is_data(&self) -> bool {
        !self.is_code()
    }

    pub fn is_user_defined(&self) -> bool {
        self.inner.user
    }

    pub fn next_to(&self) -> Option<Self> {
        let mut curr = self.clone();

        let found = unsafe { xrefblk_t_next_to(&mut curr.inner as *mut _) };

        if found {
            Some(curr)
        } else {
            None
        }
    }

    pub fn next_from(&self) -> Option<Self> {
        let mut curr = self.clone();

        let found = unsafe { xrefblk_t_next_from(&mut curr.inner as *mut _) };

        if found {
            Some(curr)
        } else {
            None
        }
    }
}

pub struct XRefToIterator<'a> {
    pub(crate) current: Option<XRef<'a>>,
}

impl<'a> Iterator for XRefToIterator<'a> {
    type Item = XRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current.take()?;
        self.current = current.next_to();
        Some(current)
    }
}

pub struct XRefFromIterator<'a> {
    pub(crate) current: Option<XRef<'a>>,
}

impl<'a> Iterator for XRefFromIterator<'a> {
    type Item = XRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current.take()?;
        self.current = current.next_from();
        Some(current)
    }
}
