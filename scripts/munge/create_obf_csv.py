from __future__ import print_function
import os
from stat import *
import sys
import pickle
import basic_block
from elftools.elf.elffile import ELFFile


def create_csvs(elff, dictf, outputd, j):
    with open(elff, 'rb') as f:
        with open(dictf, 'rb') as fd:
            addr_to_ann = pickle.load(fd)
            elffile = ELFFile(f)

            virtual_base = get_virtual_base(elffile, f)
            print("%x" % virtual_base)
            f.seek(0)

            #get offset of text section
            section = elffile.get_section_by_name(".text")
            section_offset = section['sh_offset']
            section_size = section['sh_size']

            opened = False
            b_off = 0
            b_writ = 0
            for b in bytes_from_section(f, section_offset, section_size):
                ann = addr_to_ann.get(virtual_base + section_offset + b_off, None)
                if b_writ % 1000 == 0:
                    if 'data' in locals():
                    #d-if opened:
                        data.close()
                        label.close()
                        j += 1
                    #d-opened = True
                    data = open(outputd+"/features/"+str(j)+".csv", 'w')
                    label = open(outputd+"/labels/"+str(j)+".csv", 'w')

                if ann != basic_block.ANN_SKIP:
                    #write b to data csv
                    i = 0
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
                    if ann == None:
                        label.write("0\n")
                    elif ann == basic_block.ANN_ORIGINAL:
                        label.write("0\n")
                    elif ann == basic_block.ANN_ALTERED:
                        label.write("1\n")

                    b_writ += 1

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


if __name__ == '__main__':
    # directory = "Chimera/"+ROOT_OBF_FOLDER+"/obf/"
    # mode = os.stat(directory).st_mode
    # if S_ISDIR(mode):
    #     j = 0
    #     for filename in os.listdir(directory):
    #         print(filename)
    #         j = create_csvs(directory + filename, j)
    #         print(j)
    # else:
    #     print(directory+" is not a existing directory.")

    if len(sys.argv) != 5:
        print("Please supply an unannotated, obfuscated binary as the first argument, a dictionary of obfuscation "
              "labels for the second argument, an output folder for csvs for the third argument, and lastly the "
              "starting number for the csvs as the fourth")
        sys.exit(1)

    elff = sys.argv[1]
    dictf = sys.argv[2]
    outputd = sys.argv[3]
    j = int(sys.argv[4])

    j = create_csvs(elff, dictf, outputd, j)
    rval = open("create_obf_csv.py.next_csv", "w")
    rval.write(str(j+1))

    #TODO: ltj: rval.close ?
