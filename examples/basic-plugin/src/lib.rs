use idalib::{IDA, IDAError, IDAPlugin, IDB, plugin};

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
    fn init(ida: &mut IDA, _idb: &mut IDB) -> Result<Self, IDAError> {
        ida.msg("[basic-plugin] init\n")?;
        Ok(BasicPlugin { run_count: 0 })
    }

    fn run(&mut self, ida: &mut IDA, _idb: &mut IDB, _arg: usize) -> Result<(), IDAError> {
        self.run_count += 1;
        ida.msg(&format!("[basic-plugin] run (count: {})\n", self.run_count))?;
        Ok(())
    }

    fn term(&mut self, ida: &mut IDA, _idb: &mut IDB) -> Result<(), IDAError> {
        ida.msg("[basic-plugin] term\n")?;
        Ok(())
    }
}
