use std::marker::PhantomData;

use crate::ffi::{self, BADADDR};
use crate::idb::IDB;
use crate::Address;

/// Represents an entry point (export) in an IDA database.
///
/// Each entry point has an address and an ordinal. Its name and
/// forwarder string are fetched lazily from the database when
/// [`name`](Self::name) or [`forwarder`](Self::forwarder) is called.
#[derive(Debug)]
pub struct Entry<'a> {
    address: Address,
    ordinal: u64,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Entry<'a> {
    /// The virtual address of the entry point.
    pub fn address(&self) -> Address {
        self.address
    }

    /// The ordinal number of the entry point.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// The name of the entry point, if one is set.
    ///
    /// This is fetched from the database on each call.
    pub fn name(&self) -> Option<String> {
        ffi::entry::entry_name(self.ordinal)
    }

    /// The forwarder string (e.g. `"KERNEL32.BaseThreadInitThunk"`),
    /// if this entry point is a forwarded export.
    ///
    /// This is fetched from the database on each call.
    pub fn forwarder(&self) -> Option<String> {
        ffi::entry::entry_forwarder(self.ordinal)
    }
}

/// An iterator over the entry points (exports) in an IDA database.
///
/// Yields [`Entry`] values for each entry point, skipping any that
/// map to [`BADADDR`]. The name and forwarder are *not* fetched
/// during iteration – they are retrieved lazily when the
/// corresponding accessor is called on the [`Entry`].
pub struct EntryIterator<'a> {
    index: usize,
    limit: usize,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> EntryIterator<'a> {
    pub(crate) fn new() -> Self {
        let limit = ffi::entry::entry_qty();
        Self {
            index: 0,
            limit,
            _marker: PhantomData,
        }
    }
}

impl<'a> Iterator for EntryIterator<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.index >= self.limit {
                return None;
            }

            let ord = ffi::entry::entry_ordinal(self.index);
            self.index += 1;

            let ea = ffi::entry::entry_address(ord);
            if ea == ffi::from_ea(BADADDR) {
                continue;
            }

            return Some(Entry {
                address: ea,
                ordinal: ord,
                _marker: PhantomData,
            });
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.limit.saturating_sub(self.index);
        (0, Some(remaining))
    }
}

/// Returns an iterator over all entry points (exports) in the database.
///
/// The `_idb` parameter ensures the database is available and ties the
/// iterator's lifetime to the database.
pub fn entries(_idb: &IDB) -> EntryIterator<'_> {
    EntryIterator::new()
}