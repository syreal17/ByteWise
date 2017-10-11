from elftools.elf.elffile import ELFFile
from create_obf_csv import get_virtual_base
import sys

if __name__ == "__main__":
    elff = open(sys.argv[1], "rb")
    elffile = ELFFile(elff)

    virtual_base = get_virtual_base(elffile, elff)
    elff.seek(0)

    # get offset of text section
    section = elffile.get_section_by_name(".text")
    section_offset = section['sh_offset']
    section_size = section['sh_size']

    print("%x = virtual base" % virtual_base)
    print("%x = text offset" % section_offset)

