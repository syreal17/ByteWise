import sys
from elftools.elf.elffile import ELFFile



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("First and only argument is elf file")

    f = open(sys.argv[1], 'rb')
    elffile = ELFFile(f)

    # get offset of text section
    section = elffile.get_section_by_name(".text")
    section_offset = section['sh_offset']
    section_size = section['sh_size']

    print section_size