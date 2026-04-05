use idalib::ffi::ida::msg;
use idalib::{IDAError, IDAPlugin, IDB, plugin};

struct BasicPlugin {
    run_count: usize,
}

#[plugin(
    name = "basic plugin",
    comment = "this is a basic plugin written in Rust",
    help = "this plugin does nothing useful",
    hotkey = "Ctrl-Shift-B",
    kind = resident,
)]
impl IDAPlugin for BasicPlugin {
    fn init(_idb: &mut IDB) -> Result<Self, IDAError> {
        unsafe { msg("[basic-plugin] init\n").ok() };
        Ok(BasicPlugin { run_count: 0 })
    }

    fn run(&mut self, _idb: &mut IDB, _arg: usize) -> Result<(), IDAError> {
        self.run_count += 1;
        unsafe { msg(&format!("[basic-plugin] run (count: {})\n", self.run_count)).ok() };
        Ok(())
    }

    fn term(&mut self, _idb: &mut IDB) -> Result<(), IDAError> {
        unsafe { msg("[basic-plugin] term\n").ok() };
        Ok(())
    }
}
