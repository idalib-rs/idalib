// Functions whose symbols aren't valid C identifiers, which IDA 9.5 keeps
// verbatim by default (`GarbleNames = 0` in `ida.cfg`), so that the decompiler
// wraps them in backticks (e.g., `#memcpy` in ARM64EC binaries).
//
// Build: cc -arch x86_64 -O0 -o garble_names garble_names.c

int hash_name(int x) __asm__("_has#hash");
int space_name(int x) __asm__("_has space");
int star_name(int x) __asm__("_has*star?");

int hash_name(int x) { return x + 1; }
int space_name(int x) { return x + 2; }
int star_name(int x) { return x + 3; }

int main(int argc, char **argv) {
    (void)argv;
    return hash_name(argc) + space_name(argc) + star_name(argc);
}
