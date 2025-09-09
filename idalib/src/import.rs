use std::marker::PhantomData;

use crate::Address;
use crate::ffi::nalt::idalib_get_imports;
use crate::idb::IDB;

#[derive(Debug, Clone)]
pub struct Import {
    pub module_name: String,
    pub function_name: String,
    pub address: Address,
    pub ordinal: u32,
}

pub struct ImportIterator<'a> {
    imports: Vec<Import>,
    current_index: usize,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> ImportIterator<'a> {
    pub(crate) fn new() -> Self {
        let mut module_names = Vec::new();
        let mut import_names = Vec::new();
        let mut addresses = Vec::new();
        let mut ordinals = Vec::new();

        unsafe {
            idalib_get_imports(
                &mut module_names,
                &mut import_names,
                &mut addresses,
                &mut ordinals,
            );
        }

        let imports = module_names
            .into_iter()
            .zip(import_names)
            .zip(addresses)
            .zip(ordinals)
            .map(
                |(((module_name, function_name), address), ordinal)| Import {
                    module_name,
                    function_name,
                    address,
                    ordinal,
                },
            )
            .collect();

        Self {
            imports,
            current_index: 0,
            _marker: PhantomData,
        }
    }
}

impl<'a> Iterator for ImportIterator<'a> {
    type Item = Import;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index < self.imports.len() {
            let import = self.imports[self.current_index].clone();
            self.current_index += 1;
            Some(import)
        } else {
            None
        }
    }
}
