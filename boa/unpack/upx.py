class UpxUnpacker:
    """
    Generic UPX unpacker class
    """

    def __init__(self, output_path, debug=False):
        super(UpxUnpacker, self).__init__(debug=debug)
        self.output_path = output_path
        self.base_addr = 0

    def set_dump_range(self, base, start, end):
        # Set some variables used to identify when a dump should occur
        self.base_addr = base
        self.start_addr = start
        self.end_addr = end

    def save_unpacked_file(self):
        # Save the module to disk in it's unpacked state
        with open(self.output_path, "wb") as up:
            mm = self.get_address_map(self.base_addr)
            up.write(self.mem_read(mm.get_base(), mm.get_size()))
            # TODO: Fixup the import table after dumping

    def code_hook(self, emu, addr, size, ctx):
        if self.end_addr >= addr >= self.start_addr:
            print("[*] Section hop signature hit, dumping module")
            self.save_unpacked_file()
            self.stop()
        return True


def run_unpack(outfile: str):
    unpacker = UpxUnpacker(outfile)

    # Load the module
    module = unpacker.load_module(args.file)
    base = module.get_base()

    # Get the section info for "UPX0" to detect the section hop
    upx0 = module.get_section_by_name("UPX0")

    start = base + upx0.VirtualAddress
    end = start + upx0.Misc_VirtualSize

    unpacker.set_dump_range(base, start, end)
    # Add the callback
    unpacker.add_code_hook(unpacker.code_hook)

    # Emulate the module
    unpacker.run_module(module)
