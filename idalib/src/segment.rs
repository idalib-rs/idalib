use std::marker::PhantomData;
use std::mem;
use std::pin::Pin;

use autocxx::moveit::Emplace;
use bitflags::bitflags;

use crate::ffi::range_t;
use crate::ffi::segment::*;
use crate::idb::IDB;
use crate::Address;

pub struct Segment<'a> {
    ptr: *mut segment_t,
    _lock: Pin<Box<lock_segment>>,
    _marker: PhantomData<&'a IDB>,
}

pub type SegmentId = usize;

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SegmentPermissions: u8 {
        const EXEC = SEGPERM_EXEC as _;
        const WRITE = SEGPERM_WRITE as _;
        const READ = SEGPERM_READ as _;
    }
}

impl SegmentPermissions {
    pub fn is_executable(&self) -> bool {
        self.contains(SegmentPermissions::EXEC)
    }

    pub fn is_writable(&self) -> bool {
        self.contains(SegmentPermissions::WRITE)
    }

    pub fn is_readable(&self) -> bool {
        self.contains(SegmentPermissions::READ)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SegmentAlignment {
    Abs = saAbs as _,
    RelByte = saRelByte as _,
    RelWord = saRelWord as _,
    RelPara = saRelPara as _,
    RelPage = saRelPage as _,
    RelDble = saRelDble as _,
    Rel4K = saRel4K as _,
    Group = saGroup as _,
    Rel32Bytes = saRel32Bytes as _,
    Rel64Bytes = saRel64Bytes as _,
    RelQword = saRelQword as _,
    Rel128Bytes = saRel128Bytes as _,
    Rel512Bytes = saRel512Bytes as _,
    Rel1024Bytes = saRel1024Bytes as _,
    Rel2048Bytes = saRel2048Bytes as _,
}

impl SegmentAlignment {
    pub fn is_abs(&self) -> bool {
        matches!(self, Self::Abs)
    }

    pub fn is_rel_byte(&self) -> bool {
        matches!(self, Self::RelByte)
    }

    pub fn is_rel_word(&self) -> bool {
        matches!(self, Self::RelWord)
    }

    pub fn is_rel_para(&self) -> bool {
        matches!(self, Self::RelPara)
    }

    pub fn is_rel_page(&self) -> bool {
        matches!(self, Self::RelPage)
    }

    pub fn is_rel_dble(&self) -> bool {
        matches!(self, Self::RelDble)
    }

    pub fn is_rel_4k(&self) -> bool {
        matches!(self, Self::Rel4K)
    }

    pub fn is_group(&self) -> bool {
        matches!(self, Self::Group)
    }

    pub fn is_rel_32_bytes(&self) -> bool {
        matches!(self, Self::Rel32Bytes)
    }

    pub fn is_rel_64_bytes(&self) -> bool {
        matches!(self, Self::Rel64Bytes)
    }

    pub fn is_rel_qword(&self) -> bool {
        matches!(self, Self::RelQword)
    }

    pub fn is_rel_128_bytes(&self) -> bool {
        matches!(self, Self::Rel128Bytes)
    }

    pub fn is_rel_512_bytes(&self) -> bool {
        matches!(self, Self::Rel512Bytes)
    }

    pub fn is_rel_1024_bytes(&self) -> bool {
        matches!(self, Self::Rel1024Bytes)
    }

    pub fn is_rel_2048_bytes(&self) -> bool {
        matches!(self, Self::Rel2048Bytes)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SegmentType {
    NORM = SEG_NORM as _,
    XTRN = SEG_XTRN as _,
    CODE = SEG_CODE as _,
    DATA = SEG_DATA as _,
    IMP = SEG_IMP as _,
    GRP = SEG_GRP as _,
    NULL = SEG_NULL as _,
    UNDF = SEG_UNDF as _,
    BSS = SEG_BSS as _,
    ABSSYM = SEG_ABSSYM as _,
    COMM = SEG_COMM as _,
    IMEM = SEG_IMEM as _,
}

impl SegmentType {
    pub fn is_normal(&self) -> bool {
        matches!(self, Self::NORM)
    }

    pub fn is_norm(&self) -> bool {
        self.is_normal()
    }

    pub fn is_extern(&self) -> bool {
        matches!(self, Self::XTRN)
    }

    pub fn is_xtrn(&self) -> bool {
        self.is_extern()
    }

    pub fn is_code(&self) -> bool {
        matches!(self, Self::CODE)
    }

    pub fn is_data(&self) -> bool {
        matches!(self, Self::DATA)
    }

    pub fn is_import(&self) -> bool {
        matches!(self, Self::IMP)
    }

    pub fn is_imp(&self) -> bool {
        self.is_import()
    }

    pub fn is_group(&self) -> bool {
        matches!(self, Self::GRP)
    }

    pub fn is_grp(&self) -> bool {
        self.is_group()
    }

    pub fn is_bss(&self) -> bool {
        matches!(self, Self::BSS)
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::NULL)
    }

    pub fn is_absym(&self) -> bool {
        matches!(self, Self::ABSSYM)
    }

    pub fn is_comm(&self) -> bool {
        matches!(self, Self::COMM)
    }

    pub fn is_imem(&self) -> bool {
        matches!(self, Self::IMEM)
    }

    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::UNDF)
    }

    pub fn is_undf(&self) -> bool {
        self.is_undefined()
    }
}

impl<'a> Segment<'a> {
    pub(crate) fn from_ptr(ptr: *mut segment_t) -> Self {
        let lock = unsafe { Box::emplace(lock_segment::new(ptr)) };
        Self {
            ptr,
            _lock: lock,
            _marker: PhantomData,
        }
    }

    fn as_range_t(&self) -> *const range_t {
        self.ptr.cast()
    }

    pub fn start_address(&self) -> Address {
        unsafe { (*self.as_range_t()).start_ea.into() }
    }

    pub fn end_address(&self) -> Address {
        unsafe { (*self.as_range_t()).end_ea.into() }
    }

    pub fn len(&self) -> usize {
        unsafe { (*self.as_range_t()).size().0 as _ }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains_address(&self, addr: Address) -> bool {
        unsafe { (*self.as_range_t()).contains(addr.into()) }
    }

    pub fn name(&self) -> Option<String> {
        let name = unsafe { idalib_segm_name(self.ptr) }.ok()?;

        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    pub fn alignment(&self) -> SegmentAlignment {
        unsafe { mem::transmute(idalib_segm_align(self.ptr)) }
    }

    pub fn permissions(&self) -> SegmentPermissions {
        let bits = unsafe { idalib_segm_perm(self.ptr) };
        SegmentPermissions::from_bits_retain(bits)
    }

    pub fn bitness(&self) -> usize {
        (unsafe { idalib_segm_bitness(self.ptr) }) as usize
    }

    pub fn r#type(&self) -> SegmentType {
        unsafe { mem::transmute(idalib_segm_type(self.ptr)) }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let size = self.len();
        let mut buf = Vec::with_capacity(size);

        let Ok(new_len) = (unsafe { idalib_segm_bytes(self.ptr, &mut buf) }) else {
            return Vec::with_capacity(0);
        };

        unsafe {
            buf.set_len(new_len);
        }

        buf
    }

    pub fn address_bits(&self) -> u32 {
        unsafe { (*self.ptr).abits().0 as _ }
    }

    pub fn address_bytes(&self) -> usize {
        unsafe { (*self.ptr).abytes().0 as _ }
    }

    pub fn is_16bit(&self) -> bool {
        unsafe { (*self.ptr).is_16bit() }
    }

    pub fn is_32bit(&self) -> bool {
        unsafe { (*self.ptr).is_32bit() }
    }

    pub fn is_64bit(&self) -> bool {
        unsafe { (*self.ptr).is_64bit() }
    }

    pub fn is_hidden(&self) -> bool {
        unsafe { (*self.ptr).is_hidden_segtype() }
    }

    pub fn is_loader(&self) -> bool {
        unsafe { (*self.ptr).is_loader_segm() }
    }

    pub fn is_header(&self) -> bool {
        unsafe { (*self.ptr).is_header_segm() }
    }

    pub fn is_ephemeral(&self) -> bool {
        unsafe { (*self.ptr).is_ephemeral_segm() }
    }

    pub fn is_debugger(&self) -> bool {
        unsafe { (*self.ptr).is_debugger_segm() }
    }

    pub fn is_visible(&self) -> bool {
        unsafe { (*self.ptr).is_visible_segm() }
    }

    pub fn is_extern(&self) -> bool {
        self.r#type().is_extern()
    }

    pub fn is_code_segment(&self) -> bool {
        self.r#type().is_code()
    }

    pub fn is_data_segment(&self) -> bool {
        self.r#type().is_data()
    }

    pub fn is_import_segment(&self) -> bool {
        self.r#type().is_import()
    }

    pub fn is_bss_segment(&self) -> bool {
        self.r#type().is_bss()
    }

    pub fn is_normal_segment(&self) -> bool {
        self.r#type().is_normal()
    }
}
