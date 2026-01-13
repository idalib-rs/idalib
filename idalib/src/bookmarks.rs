use std::ffi::CString;
use std::marker::PhantomData;
use std::ops::Deref;

use crate::ffi::BADADDR;
use crate::ffi::bookmarks::{
    idalib_bookmarks_t_erase, idalib_bookmarks_t_find_index, idalib_bookmarks_t_get,
    idalib_bookmarks_t_get_desc, idalib_bookmarks_t_mark, idalib_bookmarks_t_size,
};

use crate::idb::IDB;
use crate::refs::{HasId, Id, Ref, RefMut};
use crate::{Address, IDAError};

const BOOKMARKS_BAD_INDEX: u32 = 0xffffffff; // (uint32(-1))

pub struct Bookmark {
    index: u32,
}

impl HasId for Bookmark {
    fn id(&self) -> Id<Self> {
        Id::new(self.index as usize)
    }
}

impl From<u32> for Id<Bookmark> {
    fn from(index: u32) -> Self {
        Id::new(index as usize)
    }
}

impl Bookmark {
    pub(crate) fn from_index(index: u32) -> Self {
        Self { index }
    }

    pub fn address(&self) -> Option<Address> {
        let addr = unsafe { idalib_bookmarks_t_get(self.index.into()) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn description(&self) -> Option<String> {
        let s = unsafe { idalib_bookmarks_t_get_desc(self.index.into()) };
        if s.is_empty() { None } else { Some(s) }
    }

    pub fn set_description(&mut self, desc: impl AsRef<str>) -> Result<(), IDAError> {
        let addr = self.address().ok_or_else(|| {
            IDAError::ffi_with(format!(
                "bookmark at index {} has no valid address",
                self.index
            ))
        })?;

        let desc = CString::new(desc.as_ref()).map_err(IDAError::ffi)?;
        let slot =
            unsafe { idalib_bookmarks_t_mark(addr.into(), self.index.into(), desc.as_ptr()) };

        if slot == BOOKMARKS_BAD_INDEX {
            Err(IDAError::ffi_with(format!(
                "failed to set bookmark description at index {}",
                self.index
            )))
        } else {
            Ok(())
        }
    }
}

pub struct Bookmarks<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Bookmarks<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn get_by_id(&self, id: impl Into<Id<Bookmark>>) -> Option<Ref<'a, Bookmark>> {
        let index = id.into().index() as u32;
        if index >= self.len() as u32 {
            return None;
        }
        Some(Ref::new(Bookmark::from_index(index)))
    }

    pub fn get_at(&self, ea: Address) -> Option<Ref<'a, Bookmark>> {
        let index = self.resolve_index(ea)?;
        Some(Ref::new(Bookmark::from_index(index)))
    }

    fn resolve_index(&self, ea: Address) -> Option<u32> {
        let index = unsafe { idalib_bookmarks_t_find_index(ea.into()) };
        (index != BOOKMARKS_BAD_INDEX).then_some(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = Ref<'a, Bookmark>> + 'a {
        (0..self.len()).filter_map(|i| {
            let index = i as u32;
            (index < unsafe { idalib_bookmarks_t_size() })
                .then(|| Ref::new(Bookmark::from_index(index)))
        })
    }

    pub fn len(&self) -> usize {
        unsafe { idalib_bookmarks_t_size() as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct BookmarksMut<'a> {
    _marker: PhantomData<&'a mut IDB>,
}

impl<'a> Deref for BookmarksMut<'a> {
    type Target = Bookmarks<'a>;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self as *const BookmarksMut as *const Bookmarks) }
    }
}

impl<'a> BookmarksMut<'a> {
    pub(crate) fn new(_: &'a mut IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn get_by_id_mut(&mut self, id: impl Into<Id<Bookmark>>) -> Option<RefMut<'a, Bookmark>> {
        let index = id.into().index() as u32;
        if index >= self.len() as u32 {
            return None;
        }
        Some(RefMut::new(Bookmark::from_index(index)))
    }

    pub fn get_at_mut(&mut self, ea: Address) -> Option<RefMut<'a, Bookmark>> {
        let index = self.resolve_index(ea)?;
        Some(RefMut::new(Bookmark::from_index(index)))
    }

    pub fn mark(&mut self, ea: Address, desc: impl AsRef<str>) -> Result<Id<Bookmark>, IDAError> {
        self.mark_with(ea, self.len(), desc)
    }

    /// NOTE:
    /// * Adding a bookmark at an already marked address marks an overlaid bookmark
    /// * Adding a bookmark at an already used index has no effect and no error is returned
    /// * Adding a bookmark at an index > `len()` increments `len()` accordingly, while leaving
    ///   the unused bookmark slots empty
    pub fn mark_with(
        &mut self,
        ea: Address,
        id: impl Into<Id<Bookmark>>,
        desc: impl AsRef<str>,
    ) -> Result<Id<Bookmark>, IDAError> {
        let index = id.into().index() as u32;
        let desc = CString::new(desc.as_ref()).map_err(IDAError::ffi)?;

        let slot = unsafe { idalib_bookmarks_t_mark(ea.into(), index.into(), desc.as_ptr()) };

        if slot != BOOKMARKS_BAD_INDEX {
            Ok(Id::new(slot as usize))
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to mark bookmark at address {ea:#x}, index {index}"
            )))
        }
    }

    /// NOTE: When a bookmark is erased, all subsequent indices are decremented to fill the gap.
    /// This means that `Id<Bookmark>` values with index >= erased index become invalid.
    pub fn erase_by_id(&mut self, id: impl Into<Id<Bookmark>>) -> Result<(), IDAError> {
        let index = id.into().index() as u32;

        // Prevent IDA's internal error 1312 that triggers when an invalid index is supplied
        if index >= self.len() as u32 {
            return Err(IDAError::ffi_with(format!(
                "failed to erase bookmark at index {index}"
            )));
        }

        if unsafe { idalib_bookmarks_t_erase(index.into()) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to erase bookmark at index {index}"
            )))
        }
    }

    pub fn erase_at(&mut self, ea: Address) -> Result<(), IDAError> {
        let index = self.resolve_index(ea).ok_or_else(|| {
            IDAError::ffi_with(format!("failed to find bookmark for address {ea:#x}"))
        })?;
        self.erase_by_id(index)
    }
}
