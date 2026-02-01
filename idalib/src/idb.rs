use std::ffi::CString;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ops::{Bound, RangeBounds};
use std::path::{Path, PathBuf};

use crate::ffi::BADADDR;
use crate::ffi::bytes::*;
use crate::ffi::comments::{append_cmt, idalib_get_cmt, set_cmt};
use crate::ffi::conversions::idalib_ea2str;
use crate::ffi::entry::{get_entry, get_entry_ordinal, get_entry_qty};
use crate::ffi::func::{
    get_func, get_func_qty, getn_func, idalib_get_func_cmt, idalib_set_func_cmt,
};
use crate::ffi::hexrays::{decompile_func, init_hexrays_plugin, term_hexrays_plugin};
use crate::ffi::ida::{
    auto_wait, close_database_with, make_signatures, open_database_quiet, set_screen_ea,
};
use crate::ffi::insn::decode;
use crate::ffi::loader::find_plugin;
use crate::ffi::name::idalib_get_ea_name;
use crate::ffi::processor::get_ph;
use crate::ffi::search::{
    idalib_bin_search, idalib_find_binary, idalib_find_defined, idalib_find_imm, idalib_find_text,
    idalib_parse_binpat_str,
};
use crate::ffi::segment::{
    get_segm_by_name, get_segm_qty, getnseg, getseg, idalib_get_fileregion_ea,
    idalib_get_fileregion_offset,
};
use crate::ffi::strings::{idalib_get_max_strlit_length, idalib_get_strlit_contents};
use crate::ffi::util::{is_align_insn, next_head, prev_head, str2reg};
use crate::ffi::xref::{xrefblk_t, xrefblk_t_first_from, xrefblk_t_first_to};

use crate::bookmarks::Bookmarks;
use crate::decompiler::CFunction;
use crate::func::{Function, FunctionId};
use crate::import::ImportIterator;
use crate::insn::{Insn, Register};
use crate::meta::{Metadata, MetadataMut};
use crate::name::NameList;
use crate::plugin::Plugin;
use crate::processor::Processor;
use crate::segment::{Segment, SegmentId};
use crate::strings::StringList;
use crate::xref::{XRef, XRefFromIterator, XRefQuery, XRefToIterator};
use crate::{Address, AddressFlags, IDAError, IDARuntimeHandle, prepare_library};

pub struct IDB {
    path: PathBuf,
    save: bool,
    decompiler: bool,
    _guard: IDARuntimeHandle,
    _marker: PhantomData<*const ()>,
}

#[derive(Debug, Clone)]
pub struct IDBOpenOptions {
    idb: Option<PathBuf>,
    ftype: Option<String>,

    save: bool,
    auto_analyse: bool,
}

impl Default for IDBOpenOptions {
    fn default() -> Self {
        Self {
            idb: None,
            ftype: None,
            save: false,
            auto_analyse: true,
        }
    }
}

impl IDBOpenOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn idb(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.idb = Some(path.as_ref().to_owned());
        self
    }

    pub fn save(&mut self, save: bool) -> &mut Self {
        self.save = save;
        self
    }

    pub fn file_type(&mut self, ftype: impl AsRef<str>) -> &mut Self {
        self.ftype = Some(ftype.as_ref().to_owned());
        self
    }

    pub fn auto_analyse(&mut self, auto_analyse: bool) -> &mut Self {
        self.auto_analyse = auto_analyse;
        self
    }

    pub fn open(&self, path: impl AsRef<Path>) -> Result<IDB, IDAError> {
        let mut args = Vec::new();

        if let Some(ftype) = self.ftype.as_ref() {
            args.push(format!("-T{ftype}"));
        }

        if let Some(idb_path) = self.idb.as_ref() {
            args.push("-c".to_owned());
            args.push(format!("-o{}", idb_path.display()));
        }

        IDB::open_full_with(path, self.auto_analyse, self.save, &args)
    }
}

impl IDB {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IDAError> {
        Self::open_with(path, true, false)
    }

    pub fn open_with(
        path: impl AsRef<Path>,
        auto_analyse: bool,
        save: bool,
    ) -> Result<Self, IDAError> {
        Self::open_full_with(path, auto_analyse, save, &[] as &[&str])
    }

    fn open_full_with(
        path: impl AsRef<Path>,
        auto_analyse: bool,
        save: bool,
        args: &[impl AsRef<str>],
    ) -> Result<Self, IDAError> {
        let _guard = prepare_library();
        let path = path.as_ref();

        if !path.exists() || !path.is_file() {
            return Err(IDAError::not_found(path));
        }

        open_database_quiet(path, auto_analyse, args)?;

        let decompiler = unsafe { init_hexrays_plugin(0.into()) };

        Ok(Self {
            path: path.to_owned(),
            save,
            decompiler,
            _guard,
            _marker: PhantomData,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save_on_close(&mut self, status: bool) {
        self.save = status;
    }

    pub fn auto_wait(&mut self) -> bool {
        unsafe { auto_wait() }
    }

    pub fn set_screen_address(&mut self, ea: Address) {
        set_screen_ea(ea.into());
    }

    pub fn make_signatures(&mut self, only_pat: bool) -> Result<(), IDAError> {
        make_signatures(only_pat)
    }

    pub fn decompiler_available(&self) -> bool {
        self.decompiler
    }

    pub fn meta(&self) -> Metadata<'_> {
        Metadata::new()
    }

    pub fn meta_mut(&mut self) -> MetadataMut<'_> {
        MetadataMut::new()
    }

    pub fn imagebase(&self) -> Address {
        self.meta().imagebase()
    }

    pub fn processor(&self) -> Processor<'_> {
        let ptr = unsafe { get_ph() };
        Processor::from_ptr(ptr)
    }

    pub fn entries(&self) -> EntryPointIter<'_> {
        let limit = unsafe { get_entry_qty() };
        EntryPointIter {
            index: 0,
            limit,
            _marker: PhantomData,
        }
    }

    pub fn function_at(&self, ea: Address) -> Option<Function<'_>> {
        let ptr = unsafe { get_func(ea.into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Function::from_ptr(ptr))
    }

    pub fn next_head(&self, ea: Address) -> Option<Address> {
        self.next_head_with(ea, BADADDR.into())
    }

    pub fn next_head_with(&self, ea: Address, max_ea: Address) -> Option<Address> {
        let next = unsafe { next_head(ea.into(), max_ea.into()) };
        if next == BADADDR {
            None
        } else {
            Some(next.into())
        }
    }

    pub fn prev_head(&self, ea: Address) -> Option<Address> {
        self.prev_head_with(ea, 0)
    }

    pub fn prev_head_with(&self, ea: Address, min_ea: Address) -> Option<Address> {
        let prev = unsafe { prev_head(ea.into(), min_ea.into()) };
        if prev == BADADDR {
            None
        } else {
            Some(prev.into())
        }
    }

    pub fn insn_at(&self, ea: Address) -> Option<Insn> {
        let insn = decode(ea.into())?;
        Some(Insn::from_repr(insn))
    }

    pub fn decompile<'a>(&'a self, f: &Function<'a>) -> Result<CFunction<'a>, IDAError> {
        self.decompile_with(f, false)
    }

    pub fn decompile_with<'a>(
        &'a self,
        f: &Function<'a>,
        all_blocks: bool,
    ) -> Result<CFunction<'a>, IDAError> {
        if !self.decompiler {
            return Err(IDAError::ffi_with("no decompiler available"));
        }

        Ok(unsafe {
            decompile_func(f.as_ptr(), all_blocks)
                .map(|f| CFunction::new(f).expect("null pointer checked"))?
        })
    }

    pub fn function_by_id(&self, id: FunctionId) -> Option<Function<'_>> {
        let ptr = unsafe { getn_func(id) };

        if ptr.is_null() {
            return None;
        }

        Some(Function::from_ptr(ptr))
    }

    pub fn functions<'a>(&'a self) -> impl Iterator<Item = (FunctionId, Function<'a>)> + 'a {
        (0..self.function_count()).filter_map(|id| self.function_by_id(id).map(|f| (id, f)))
    }

    pub fn function_count(&self) -> usize {
        unsafe { get_func_qty() }
    }

    fn bounds_to_range(&self, range: impl RangeBounds<Address>) -> (Address, Address) {
        let start = match range.start_bound() {
            Bound::Included(&s) => s,
            Bound::Excluded(&s) => s.saturating_add(1),
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&e) => e.saturating_add(1),
            Bound::Excluded(&e) => e,
            Bound::Unbounded => BADADDR.into(),
        };
        (start, end)
    }

    pub fn heads<'a>(&'a self, range: impl RangeBounds<Address>) -> HeadsIterator<'a> {
        let (start, end) = self.bounds_to_range(range);
        HeadsIterator {
            idb: self,
            current: Some(start),
            end,
        }
    }

    pub fn segment_at(&self, ea: Address) -> Option<Segment<'_>> {
        let ptr = unsafe { getseg(ea.into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Segment::from_ptr(ptr))
    }

    pub fn segment_by_id(&self, id: SegmentId) -> Option<Segment<'_>> {
        let ptr = unsafe { getnseg((id as i32).into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Segment::from_ptr(ptr))
    }

    pub fn segment_by_name(&self, name: impl AsRef<str>) -> Option<Segment<'_>> {
        let s = CString::new(name.as_ref()).ok()?;
        let ptr = unsafe { get_segm_by_name(s.as_ptr()) };

        if ptr.is_null() {
            return None;
        }

        Some(Segment::from_ptr(ptr))
    }

    pub fn segments<'a>(&'a self) -> impl Iterator<Item = (SegmentId, Segment<'a>)> + 'a {
        (0..self.segment_count()).filter_map(|id| self.segment_by_id(id).map(|s| (id, s)))
    }

    pub fn segment_count(&self) -> usize {
        unsafe { get_segm_qty().0 as _ }
    }

    /// Get file offset corresponding to the given address.
    ///
    /// Returns -1 if the address can't be mapped to a file offset.
    pub fn get_fileregion_offset(&self, ea: Address) -> i64 {
        unsafe { idalib_get_fileregion_offset(ea.into()) }
    }

    /// Get linear address corresponding to the given file offset.
    ///
    /// Returns BADADDR if the offset can't be mapped to an address.
    pub fn get_fileregion_ea(&self, offset: i64) -> Address {
        let result = unsafe { idalib_get_fileregion_ea(offset) };
        result.into()
    }

    pub fn register_by_name(&self, name: impl AsRef<str>) -> Option<Register> {
        let s = CString::new(name.as_ref()).ok()?;
        let id = unsafe { str2reg(s.as_ptr()).0 };

        if id == -1 { None } else { Some(id as _) }
    }

    pub fn insn_alignment_at(&self, ea: Address) -> Option<usize> {
        let align = unsafe { is_align_insn(ea.into()).0 };
        if align == 0 { None } else { Some(align as _) }
    }

    pub fn first_xref_from(&self, ea: Address, flags: XRefQuery) -> Option<XRef<'_>> {
        let mut xref = MaybeUninit::<xrefblk_t>::zeroed();
        let found =
            unsafe { xrefblk_t_first_from(xref.as_mut_ptr(), ea.into(), flags.bits().into()) };

        if found {
            Some(XRef::from_repr(unsafe { xref.assume_init() }))
        } else {
            None
        }
    }

    pub fn first_xref_to(&self, ea: Address, flags: XRefQuery) -> Option<XRef<'_>> {
        let mut xref = MaybeUninit::<xrefblk_t>::zeroed();
        let found =
            unsafe { xrefblk_t_first_to(xref.as_mut_ptr(), ea.into(), flags.bits().into()) };

        if found {
            Some(XRef::from_repr(unsafe { xref.assume_init() }))
        } else {
            None
        }
    }

    pub fn xrefs_to<'a>(&'a self, ea: Address) -> impl Iterator<Item = XRef<'a>> + 'a {
        let first_xref = self.first_xref_to(ea, XRefQuery::ALL);
        XRefToIterator {
            current: first_xref,
        }
    }

    pub fn xrefs_from<'a>(&'a self, ea: Address) -> impl Iterator<Item = XRef<'a>> + 'a {
        let first_xref = self.first_xref_from(ea, XRefQuery::ALL);
        XRefFromIterator {
            current: first_xref,
        }
    }

    pub fn get_cmt(&self, ea: Address) -> Option<String> {
        self.get_cmt_with(ea, false)
    }

    pub fn get_cmt_with(&self, ea: Address, rptble: bool) -> Option<String> {
        let s = unsafe { idalib_get_cmt(ea.into(), rptble) };

        if s.is_empty() { None } else { Some(s) }
    }

    pub fn get_func_cmt(&self, ea: Address) -> Option<String> {
        self.get_func_cmt_with(ea, false)
    }

    pub fn get_func_cmt_with(&self, ea: Address, rptble: bool) -> Option<String> {
        let f = self.function_at(ea)?;
        let s = unsafe { idalib_get_func_cmt(f.as_ptr() as _, rptble) }.ok()?;

        if s.is_empty() { None } else { Some(s) }
    }

    pub fn set_cmt(&self, ea: Address, comm: impl AsRef<str>) -> Result<(), IDAError> {
        self.set_cmt_with(ea, comm, false)
    }

    pub fn set_cmt_with(
        &self,
        ea: Address,
        comm: impl AsRef<str>,
        rptble: bool,
    ) -> Result<(), IDAError> {
        let s = CString::new(comm.as_ref()).map_err(IDAError::ffi)?;
        if unsafe { set_cmt(ea.into(), s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to set comment at {ea:#x}"
            )))
        }
    }

    pub fn set_func_cmt(&self, ea: Address, comm: impl AsRef<str>) -> Result<(), IDAError> {
        self.set_func_cmt_with(ea, comm, false)
    }

    pub fn set_func_cmt_with(
        &self,
        ea: Address,
        comm: impl AsRef<str>,
        rptble: bool,
    ) -> Result<(), IDAError> {
        let f = self
            .function_at(ea)
            .ok_or_else(|| IDAError::ffi_with(format!("no function found at address {ea:#x}")))?;
        let s = CString::new(comm.as_ref()).map_err(IDAError::ffi)?;
        if unsafe { idalib_set_func_cmt(f.as_ptr() as _, s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to set function comment at {ea:#x}"
            )))
        }
    }

    pub fn append_cmt(&self, ea: Address, comm: impl AsRef<str>) -> Result<(), IDAError> {
        self.append_cmt_with(ea, comm, false)
    }

    pub fn append_cmt_with(
        &self,
        ea: Address,
        comm: impl AsRef<str>,
        rptble: bool,
    ) -> Result<(), IDAError> {
        let s = CString::new(comm.as_ref()).map_err(IDAError::ffi)?;
        if unsafe { append_cmt(ea.into(), s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to append comment at {ea:#x}"
            )))
        }
    }

    pub fn remove_cmt(&self, ea: Address) -> Result<(), IDAError> {
        self.remove_cmt_with(ea, false)
    }

    pub fn remove_cmt_with(&self, ea: Address, rptble: bool) -> Result<(), IDAError> {
        if unsafe { set_cmt(ea.into(), c"".as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to remove comment at {ea:#x}"
            )))
        }
    }

    pub fn remove_func_cmt(&self, ea: Address) -> Result<(), IDAError> {
        self.remove_func_cmt_with(ea, false)
    }

    pub fn remove_func_cmt_with(&self, ea: Address, rptble: bool) -> Result<(), IDAError> {
        let f = self
            .function_at(ea)
            .ok_or_else(|| IDAError::ffi_with(format!("no function found at address {ea:#x}")))?;
        if unsafe { idalib_set_func_cmt(f.as_ptr(), c"".as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to remove comment at {ea:#x}"
            )))
        }
    }

    pub fn bookmarks(&self) -> Bookmarks<'_> {
        Bookmarks::new(self)
    }

    pub fn find_text(&self, start_ea: Address, text: impl AsRef<str>) -> Option<Address> {
        let s = CString::new(text.as_ref()).ok()?;
        let addr = unsafe { idalib_find_text(start_ea.into(), s.as_ptr()) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn find_text_iter<'a, T>(&'a self, text: T) -> impl Iterator<Item = Address> + 'a
    where
        T: AsRef<str> + 'a,
    {
        let mut cur = 0u64;
        std::iter::from_fn(move || {
            let found = self.find_text(cur, text.as_ref())?;
            cur = self.find_defined(found).unwrap_or(BADADDR.into());
            Some(found)
        })
    }

    pub fn find_imm(&self, start_ea: Address, imm: u32) -> Option<Address> {
        let addr = unsafe { idalib_find_imm(start_ea.into(), imm.into()) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn find_imm_iter<'a>(&'a self, imm: u32) -> impl Iterator<Item = Address> + 'a {
        let mut cur = 0u64;
        std::iter::from_fn(move || {
            cur = self.find_imm(cur, imm)?;
            Some(cur)
        })
    }

    pub fn find_defined(&self, start_ea: Address) -> Option<Address> {
        let addr = unsafe { idalib_find_defined(start_ea.into()) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn find_bytes(&self, pattern: impl AsRef<str>) -> Option<Address> {
        self.find_bytes_range(.., pattern)
    }

    pub fn find_bytes_range(
        &self,
        range: impl RangeBounds<Address>,
        pattern: impl AsRef<str>,
    ) -> Option<Address> {
        let (start_ea, end_ea) = self.bounds_to_range(range);
        let s = CString::new(pattern.as_ref()).ok()?;
        let addr =
            unsafe { idalib_bin_search(start_ea.into(), end_ea.into(), s.as_ptr(), 0.into()) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn find_bytes_iter<'a>(
        &'a self,
        pattern: impl AsRef<str> + 'a,
    ) -> impl Iterator<Item = Address> + 'a {
        let mut cur = 0u64;
        std::iter::from_fn(move || {
            cur = self.find_bytes_range(cur.., pattern.as_ref())?;
            let found = cur;
            cur = self.find_defined(cur).unwrap_or(BADADDR.into());
            Some(found)
        })
    }

    pub fn parse_binary_pattern(&self, pattern: impl AsRef<str>) -> Option<(Vec<u8>, Vec<u8>)> {
        let s = CString::new(pattern.as_ref()).ok()?;
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        let success = unsafe { idalib_parse_binpat_str(s.as_ptr(), &mut bytes, &mut mask) };
        if success { Some((bytes, mask)) } else { None }
    }

    pub fn find_binary(&self, bytes: &[u8], mask: &[u8]) -> Option<Address> {
        self.find_binary_range(.., bytes, mask)
    }

    pub fn find_binary_range(
        &self,
        range: impl RangeBounds<Address>,
        bytes: &[u8],
        mask: &[u8],
    ) -> Option<Address> {
        let (start_ea, end_ea) = self.bounds_to_range(range);
        if bytes.len() != mask.len() {
            return None;
        }

        let addr = unsafe {
            idalib_find_binary(
                start_ea.into(),
                end_ea.into(),
                bytes.as_ptr(),
                mask.as_ptr(),
                bytes.len(),
            )
        };

        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn strings(&self) -> StringList<'_> {
        StringList::new(self)
    }

    pub fn names(&self) -> crate::name::NameList<'_> {
        NameList::new(self)
    }

    pub fn address_to_string(&self, ea: Address) -> Option<String> {
        let s = unsafe { idalib_ea2str(ea.into()) };

        if s.is_empty() { None } else { Some(s) }
    }

    pub fn flags_at(&self, ea: Address) -> AddressFlags<'_> {
        AddressFlags::new(unsafe { get_flags(ea.into()) })
    }

    pub fn is_code(&self, ea: Address) -> bool {
        self.flags_at(ea).is_code()
    }

    pub fn is_data(&self, ea: Address) -> bool {
        self.flags_at(ea).is_data()
    }

    pub fn get_byte(&self, ea: Address) -> u8 {
        unsafe { idalib_get_byte(ea.into()) }
    }

    pub fn get_word(&self, ea: Address) -> u16 {
        unsafe { idalib_get_word(ea.into()) }
    }

    pub fn get_dword(&self, ea: Address) -> u32 {
        unsafe { idalib_get_dword(ea.into()) }
    }

    pub fn get_qword(&self, ea: Address) -> u64 {
        unsafe { idalib_get_qword(ea.into()) }
    }

    pub fn get_bytes(&self, ea: Address, size: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(size);

        let Ok(new_len) = (unsafe { idalib_get_bytes(ea.into(), &mut buf) }) else {
            return Vec::with_capacity(0);
        };

        unsafe {
            buf.set_len(new_len);
        }

        buf
    }

    pub fn get_string_at(&self, ea: Address) -> Option<String> {
        let max_len = unsafe { idalib_get_max_strlit_length(ea.into(), -1) };
        if max_len == 0 {
            return None;
        }

        let contents = unsafe { idalib_get_strlit_contents(ea.into(), max_len, -1) };
        if contents.is_empty() {
            None
        } else {
            Some(contents)
        }
    }

    pub fn get_name(&self, ea: Address) -> Option<String> {
        let name = unsafe { idalib_get_ea_name(ea.into()) };
        if name.is_empty() { None } else { Some(name) }
    }

    pub fn is_loaded(&self, ea: Address) -> bool {
        unsafe { idalib_is_loaded(ea.into()) }
    }

    pub fn is_mapped(&self, ea: Address) -> bool {
        unsafe { idalib_is_mapped(ea.into()) }
    }

    pub fn find_plugin(
        &self,
        name: impl AsRef<str>,
        load_if_needed: bool,
    ) -> Result<Plugin<'_>, IDAError> {
        let plugin = CString::new(name.as_ref()).map_err(IDAError::ffi)?;
        let ptr = unsafe { find_plugin(plugin.as_ptr(), load_if_needed) };

        if ptr.is_null() {
            Err(IDAError::ffi_with(format!(
                "failed to load {} plugin",
                name.as_ref()
            )))
        } else {
            Ok(Plugin::from_ptr(ptr))
        }
    }

    pub fn load_plugin(&self, name: impl AsRef<str>) -> Result<Plugin<'_>, IDAError> {
        self.find_plugin(name, true)
    }

    pub fn imports(&self) -> ImportIterator<'_> {
        ImportIterator::new()
    }
}

impl Drop for IDB {
    fn drop(&mut self) {
        if self.decompiler {
            unsafe {
                term_hexrays_plugin();
            }
        }
        close_database_with(self.save);
    }
}

pub struct HeadsIterator<'a> {
    idb: &'a IDB,
    current: Option<Address>,
    end: Address,
}

impl<'a> Iterator for HeadsIterator<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;

        if current >= self.end {
            self.current = None;
            return None;
        }

        let next_addr = self.idb.next_head_with(current, self.end);
        self.current = next_addr;

        Some(current)
    }
}

pub struct EntryPointIter<'a> {
    index: usize,
    limit: usize,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Iterator for EntryPointIter<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.limit {
            return None;
        }

        let ordinal = unsafe { get_entry_ordinal(self.index) };
        let addr = unsafe { get_entry(ordinal) };

        // skip?
        if addr == BADADDR {
            self.index += 1;
            return self.next();
        }

        Some(addr.into())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let lim = self.limit - self.index;
        (0, Some(lim))
    }
}
