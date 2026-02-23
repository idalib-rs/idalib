use std::ffi::CStr;
use std::marker::PhantomData;

use bitflags::bitflags;

use crate::ffi::BADADDR;
use crate::ffi::name::{
    get_nlist_ea, get_nlist_idx, get_nlist_name, get_nlist_size, is_in_nlist, is_public_name,
    is_weak_name,
};

use crate::Address;
use crate::idb::IDB;

pub type NameIndex = usize;

pub struct NameList<'a> {
    _marker: PhantomData<&'a IDB>,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct NameProperties: u8 {
        const PUBLIC = 0x01;
        const WEAK = 0x02;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SetNameFlags: i32 {
        const SN_CHECK        = 0x00;
        const SN_NOCHECK      = 0x01;
        const SN_PUBLIC       = 0x02;
        const SN_NON_PUBLIC   = 0x04;
        const SN_WEAK         = 0x08;
        const SN_NON_WEAK     = 0x10;
        const SN_AUTO         = 0x20;
        const SN_NON_AUTO     = 0x40;
        const SN_NOLIST       = 0x80;
        const SN_NOWARN       = 0x100;
        const SN_LOCAL        = 0x200;
        const SN_IDBENC       = 0x400;
        const SN_FORCE        = 0x800;
        const SN_NODUMMY      = 0x1000;
        const SN_DELTAIL      = 0x2000;
        const SN_MULTI        = 0x4000;
        const SN_MULTI_FORCE  = 0x8000;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name {
    address: Address,
    name: String,
    index: NameIndex,
    properties: NameProperties,
}

impl Name {
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_public(&self) -> bool {
        self.properties.contains(NameProperties::PUBLIC)
    }

    pub fn is_weak(&self) -> bool {
        self.properties.contains(NameProperties::WEAK)
    }
}

impl<'a> NameList<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn get_by_index(&self, index: NameIndex) -> Option<Name> {
        let addr = self.get_address_by_index(index)?;
        let name = unsafe { get_nlist_name(index) };
        if name.is_null() {
            return None;
        }

        let name = unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();

        let mut properties = NameProperties::empty();

        if unsafe { is_public_name(addr.into()) } {
            properties.insert(NameProperties::PUBLIC);
        }

        if unsafe { is_weak_name(addr.into()) } {
            properties.insert(NameProperties::WEAK);
        }

        Some(Name {
            address: addr,
            name,
            index,
            properties,
        })
    }

    pub fn get_closest_by_address(&self, address: Address) -> Option<Name> {
        let index = unsafe { get_nlist_idx(address.into()) };
        self.get_by_index(index)
    }

    pub fn get_address_by_index(&self, index: NameIndex) -> Option<Address> {
        let addr = unsafe { get_nlist_ea(index) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn has_name(&self, address: Address) -> bool {
        unsafe { is_in_nlist(address.into()) }
    }

    pub fn len(&self) -> usize {
        unsafe { get_nlist_size() }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> NameListIter<'_, 'a> {
        NameListIter {
            name_list: self,
            current_index: 0,
        }
    }
}

pub struct NameListIter<'s, 'a> {
    name_list: &'s NameList<'a>,
    current_index: NameIndex,
}

impl<'s, 'a> Iterator for NameListIter<'s, 'a> {
    type Item = Name;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < self.name_list.len() {
            let name = self.name_list.get_by_index(self.current_index);

            self.current_index += 1;

            if name.is_some() {
                return name;
            }
        }
        None
    }
}
