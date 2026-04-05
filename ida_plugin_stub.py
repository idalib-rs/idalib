import idaapi

class RustBindingsStub(idaapi.plugin_t):
    flags = 0
    comment = "Stub for idalib's Rust bindings"
    help = "This plugin is a stub and does not provide any functionality."
    wanted_name = "idalib Rust Bindings"
    wanted_hotkey = ""

    def init(self):
        print(
            "[WARN] idalib's Rust bindings should be used via the `idalib` crate "
            "via crates.io or from source, not as a regular plugin."
        )
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    if not hasattr(PLUGIN_ENTRY, "_inst"):
        PLUGIN_ENTRY._inst = RustBindingsStub()
    return PLUGIN_ENTRY._inst
