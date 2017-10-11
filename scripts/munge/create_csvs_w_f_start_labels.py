from __future__ import print_function
import os

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def create_csvs(filename, j):
    with open(filename, 'rb') as f:
        addr_to_is_f_start = dict()
        elffile = ELFFile(f)

        virtual_base = get_virtual_base(elffile, f)
        print("%x" % virtual_base)
        addr_to_is_f_start = create_f_start_dict(elffile, addr_to_is_f_start)
        f.seek(0)

        #get offset of text section
        section = elffile.get_section_by_name(".text")
        section_offset = section['sh_offset']
        section_size = section['sh_size']

        opened = False
        b_off = 0
        for b in bytes_from_section(f, section_offset, section_size):
            if b_off % 1000 == 0:
                if 'data' in locals():
                #d-if opened:
                    data.close()
                    label.close()
                    j += 1
                #d-opened = True
                data = open("data/"+str(j)+".csv", 'w')
                label = open("label/"+str(j)+".csv", 'w')

            #write b to data csv
            i = 0;
            for x in range(0x0, ord(b)):
                i = x
                if i == 0:
                    data.write("0")
                    i += 1
                else:
                    data.write(",0")
            if i == 0:
                data.write("1")
            else:
                data.write(",1")
            for _ in range(ord(b)+1,0x100):
                data.write(",0")
            data.write("\n")

            #check if it's in dict, add label
            is_f_start = addr_to_is_f_start.get(virtual_base+section_offset+b_off, False)
            if is_f_start:
                label.write("1\n")
            else:
                label.write("0\n")

            b_off += 1

        data.close()
        label.close()

        return j


def bytes_from_section(f, section_offset, section_size, chunksize=8192):
    f.seek(section_offset)
    i = 0
    while True:
        chunk = f.read(chunksize)
        if chunk:
            for b in chunk:
                if i == section_size:
                    break
                i += 1
                yield b
        else:
            break


def get_virtual_base(elffile, f):
    #print("e_shoff:%x"%elffile['e_shoff'])
    #print("e_shentsize:%x"%elffile['e_shentsize'])
    section_offset = elffile['e_shoff'] + elffile['e_shentsize']
    f.seek(section_offset)
    section_header = elffile.structs.Elf_Shdr.parse_stream(f)
    return section_header['sh_addr'] - section_header['sh_offset']


def create_f_start_dict(elffile, addr_to_is_f_start):
    section = elffile.get_section_by_name('.symtab')

    if not section:
        print('No symbol table found. Perhaps this ELF has been stripped?')
        return

    if isinstance(section, SymbolTableSection):
        num_symbols = section.num_symbols()
        for i in range(0, num_symbols - 1):
            sym = section.get_symbol(i)
            if sym['st_info'].type == 'STT_FUNC': #and sym['st_info'].bind == "STB_LOCAL":
                #print("%s" % section.get_symbol(i).name)
                addr_to_is_f_start[sym['st_value']] = True
    return addr_to_is_f_start


if __name__ == '__main__':
    directory = "Chimera/bcfloop1/mal/binary/"
    j = 0
    for filename in os.listdir(directory):
        print(filename)
        j = create_csvs(directory + filename, j)
        print(j)