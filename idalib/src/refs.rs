use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use crate::idb::IDB;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id<T> {
    index: usize,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Display for Id<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.index)
    }
}

impl<T> Id<T> {
    pub(crate) fn new(index: usize) -> Self {
        Self {
            index,
            _marker: PhantomData,
        }
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }
}

impl<T> From<usize> for Id<T> {
    fn from(index: usize) -> Self {
        Id::new(index)
    }
}

pub struct Ref<'a, T> {
    inner: T,
    _marker: PhantomData<&'a IDB>,
}

impl<'a, T> Ref<'a, T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    pub fn id(&self) -> Id<T>
    where
        T: HasId,
    {
        self.inner.id()
    }
}

impl<T> Deref for Ref<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsRef<T> for Ref<'_, T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

pub struct RefMut<'a, T> {
    inner: T,
    _marker: PhantomData<&'a mut IDB>,
}

impl<'a, T> RefMut<'a, T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    pub fn id(&self) -> Id<T>
    where
        T: HasId,
    {
        self.inner.id()
    }
}

impl<T> Deref for RefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> AsRef<T> for RefMut<'_, T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsMut<T> for RefMut<'_, T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

pub trait HasId {
    fn id(&self) -> Id<Self>
    where
        Self: Sized;
}
