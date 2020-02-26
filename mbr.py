from capstone import *
import common


def parse_single_part(part):
    active_part = False
    part_start = bytearray(3)
    part_end = bytearray(3)
    sector_start = bytearray(4)
    size = bytearray(4)
    part_fs = b""

    if(part[0] == 0x80):
        active_part = True

    part_start.append(part[3])
    part_start.append(part[2])
    part_start.append(part[1])

    part_fs = part[4]

    part_end.append(part[7])
    part_end.append(part[6])
    part_end.append(part[5])

    sector_start.append(part[11])
    sector_start.append(part[10])
    sector_start.append(part[9])
    sector_start.append(part[8])

    size.append(part[15])
    size.append(part[14])
    size.append(part[13])
    size.append(part[12])

    print("\tActive Partition: " + str(active_part))
    print("\tPartition FS: " + hex(part_fs))
    print("\tStart Cylinder: " + part_start.hex())
    print("\tEnd Cylinder: " + part_end.hex())
    print("\tSector Start: " + sector_start.hex())
    print("\tPartition Size: " + str(int.from_bytes(size, byteorder='big',signed=False)))

def parse_partitions(dat):
    part1 = dat[:16]
    part2 = dat[16:32]
    part3 = dat[32:48]
    part4 = dat[48:64]

    print("Partition 1: 0x{}".format(' 0x'.join(format(x, '02x') for x in part1) ))
    parse_single_part(part1)
    print("Partition 2: 0x{}".format(' 0x'.join(format(x, '02x') for x in part2) ))
    parse_single_part(part2)
    print("Partition 3: 0x{}".format(' 0x'.join(format(x, '02x') for x in part3) ))
    parse_single_part(part3)
    print("Partition 4: 0x{}".format(' 0x'.join(format(x, '02x') for x in part4) ))
    parse_single_part(part4)

def read_mbr(file_name):
    with open(file_name, 'rb') as f:
        mbr = f.read(512) 
        ops = mbr[:446]
        part_table = mbr[446:510]
        parse_partitions(part_table)
        magic = mbr[510:]
        addr = 0x0
        md = Cs(CS_ARCH_X86, CS_MODE_16)
        ctr = 0
        print("MBR bytecode operations (not decoded):\n" + '-'*30)
        for byte in ops:
            if ctr >= 9:
                print("{} ".format(hex(byte)))
                ctr = 0
            else:
                print("{} ".format(hex(byte)), end="")
                ctr += 1
        print("\n" + '-'*30)
        tot_size = 0
        for (address, size, mnemonic, op_str) in md.disasm_lite(ops, addr):
            print("0x%x:\t%s\t%s\t%d bytes" % (address, mnemonic, op_str, size))
            tot_size += size
        print("Total size: %d" % tot_size)

        #for i in md.disasm(ops, addr):        
         #   print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')
