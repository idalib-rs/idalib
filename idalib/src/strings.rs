use std::marker::PhantomData;

use crate::ffi::bytes::idalib_get_bytes;
use crate::ffi::strings::{
    build_strlist, clear_strlist, get_strlist_qty, idalib_get_strlist_item_addr,
    idalib_get_strlist_item_length,
};
use crate::ffi::BADADDR;

use crate::idb::IDB;
use crate::Address;

pub type StringIndex = usize;

pub struct StringList<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> StringList<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn rebuild(&self) {
        unsafe { build_strlist() }
    }

    pub fn clear(&self) {
        unsafe { clear_strlist() }
    }

    pub fn get_by_index(&self, index: StringIndex) -> Option<String> {
        let addr = self.get_address_by_index(index)?;
        let size = self.get_length_by_index(index);

        // See also `IDB::get_bytes`
        let mut buf = Vec::with_capacity(size);
        let Ok(new_len) = (unsafe { idalib_get_bytes(addr.into(), &mut buf) }) else {
            return None;
        };
        unsafe {
            buf.set_len(new_len);
        }

        // TODO: switch to `String::from_utf8_lossy_owned` once it's stable
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    pub fn get_address_by_index(&self, index: StringIndex) -> Option<Address> {
        let addr = unsafe { idalib_get_strlist_item_addr(index) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    fn get_length_by_index(&self, index: StringIndex) -> usize {
        unsafe { idalib_get_strlist_item_length(index) }
    }

    pub fn len(&self) -> usize {
        unsafe { get_strlist_qty() }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> StringListIter<'_, 'a> {
        StringListIter {
            string_list: self,
            current_index: 0,
        }
    }
}

pub struct StringListIter<'s, 'a> {
    string_list: &'s StringList<'a>,
    current_index: StringIndex,
}

impl<'s, 'a> Iterator for StringListIter<'s, 'a> {
    type Item = (Address, String);

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < self.string_list.len() {
            let addr = self.string_list.get_address_by_index(self.current_index);
            let string = self.string_list.get_by_index(self.current_index);

            self.current_index += 1;

            if let (Some(addr), Some(string)) = (addr, string) {
                return Some((addr, string));
            };
            // skip invalid strings, such as:
            // - the index became invalid, such as if a string was undefined
            // - the string failed to decode (today: not UTF-8)
        }
        None
    }
}
