use crate::ffi::ida::msg;
use crate::ffi::plugin::PlugModBridge;
use crate::idb::IDB;
use crate::{IDA, IDAError};

pub trait IDAPlugin: Sized + Send + Sync + 'static {
    fn init(ida: &mut IDA, idb: &mut IDB) -> Result<Self, IDAError>;

    fn run(&mut self, ida: &mut IDA, idb: &mut IDB, arg: usize) -> Result<(), IDAError>;

    fn term(&mut self, _ida: &mut IDA, _idb: &mut IDB) -> Result<(), IDAError> {
        Ok(())
    }
}

trait IDAPluginErased: Send + Sync {
    fn run(&mut self, ida: &mut IDA, idb: &mut IDB, arg: usize) -> Result<(), IDAError>;
    fn term(&mut self, ida: &mut IDA, idb: &mut IDB) -> Result<(), IDAError>;
}

impl<P: IDAPlugin> IDAPluginErased for P {
    fn run(&mut self, ida: &mut IDA, idb: &mut IDB, arg: usize) -> Result<(), IDAError> {
        IDAPlugin::run(self, ida, idb, arg)
    }

    fn term(&mut self, ida: &mut IDA, idb: &mut IDB) -> Result<(), IDAError> {
        IDAPlugin::term(self, ida, idb)
    }
}

#[doc(hidden)]
pub struct PlugmodWrapper {
    name: &'static str,
    plugin: Box<dyn IDAPluginErased>,
}

impl PlugmodWrapper {
    pub fn new(name: &'static str, plugin: impl IDAPlugin) -> Self {
        Self {
            name,
            plugin: Box::new(plugin),
        }
    }
}

impl PlugModBridge for PlugmodWrapper {
    fn run(&mut self, arg: usize) -> bool {
        let result = IDB::current().and_then(|mut idb| {
            let mut ida = IDA::new(&idb);
            self.plugin.run(&mut ida, &mut idb, arg)
        });
        match result {
            Ok(()) => true,
            Err(e) => {
                let _ = unsafe { msg(&format!("[{}] `run` failed: {e}\n", self.name)) };
                false
            }
        }
    }

    fn term(&mut self) {
        let result = IDB::current().and_then(|mut idb| {
            let mut ida = IDA::new(&idb);
            self.plugin.term(&mut ida, &mut idb)
        });
        if let Err(e) = result {
            let _ = unsafe { msg(&format!("[{}] `term` failed: {e}\n", self.name)) };
        }
    }
}
