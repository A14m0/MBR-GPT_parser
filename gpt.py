from capstone import *
import struct
import common
from array import array
import uuid

# https://en.wikipedia.org/wiki/GUID_Partition_Table
# https://www.google.com/search?q=gpt+partition+table+layout&source=lmns&safe=strict&hl=en&ved=2ahUKEwiXma6V2ernAhXWbc0KHUqnDZYQ_AUoAHoECAEQAA
# https://docs.python.org/3/library/struct.html
# https://en.wikipedia.org/wiki/Logical_block_addressing
# https://developer.apple.com/library/archive/technotes/tn2166/_index.html#//apple_ref/doc/uid/DTS10003927-CH1-SUBSECTION11
# https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs
# https://en.wikipedia.org/wiki/Universally_unique_identifier#Encoding
# https://docs.python.org/3/library/uuid.html

def parse_guid(guid):
    final_guid = ""
    first_bytes = ""
    second_bytes = ""
    third_bytes = ""
    fourth_bytes = ""
    fifth_bytes = ""

    first = struct.unpack("<cccc", guid[:4])
    for byte in first:
        first_bytes += byte.hex()

    second = struct.unpack("<cc", guid[4:6])
    for byte in second:
        second_bytes += byte.hex()
    
    third = struct.unpack("<cc", guid[6:8])
    for byte in third:
        third_bytes += byte.hex()
    
    fourth = struct.unpack(">cc", guid[8:10])
    for byte in fourth:
        fourth_bytes += byte.hex()
    
    fifth = struct.unpack(">cccccc", guid[10:])
    for byte in fifth:
        fifth_bytes += byte.hex()
    
    final_guid = "%s-%s-%s-%s-%s" % (first_bytes, 
                                    second_bytes, 
                                    third_bytes, 
                                    fourth_bytes,
                                    fifth_bytes)
    return final_guid

def parse_flags(flags):
    flag_int = int.from_bytes(flags, "little")
    print("Flag integer: %d" % flag_int)
    platform_req = False
    efi_ign = False
    legacy_bootable = False
    read_only = False
    shadow = False
    hidden = False
    no_drive_letter = False
    successful_boot = False
    is_chrome_part = False
    is_windows_part = False
    rsrv_bits = []
    chrome_retries = []
    chrome_priority = 0

    platform_req = (flag_int & 0)
    efi_ign = (flag_int & 1)
    legacy_bootable = (flag_int & 2)
    read_only = (flag_int & 60)
    shadow = (flag_int & 61)
    hidden = (flag_int & 62)
    no_drive_letter = (flag_int & 63)
    successful_boot = (flag_int & 56)

    if read_only or shadow or hidden or no_drive_letter:
        is_windows_part = True

    for i in range(3,55):
        if flag_int & i:
            rsrv_bits.append(i)
            if i > 47 and i < 56:
                is_chrome_part = True
                if i > 52:
                    chrome_retries.append(i)
                else:
                    chrome_priority = i -48

    print("""Flags: 
    Platform Required: %s
    EFI Ignore: %s
    Legacy BIOS Bootable: %s
    Reserved bits used: """ % (platform_req, efi_ign, legacy_bootable), end="")
    print(rsrv_bits)
    if is_windows_part:
        print("""\t*** WINDOWS PARTITION FLAGS DETECTED ***
    Read-Only: %s
    Shadow Copy: %s
    Hidden Drive: %s
    No Drive Letter (no automount): %s""" %(read_only, shadow, hidden, no_drive_letter))
    if is_chrome_part:
        print("""\t*** CHROME OS PARTITION FLAGS DETECTED ***
    Successful Boot: %s""" % successful_boot)
        print("\tTries remaining: " + str(chrome_retries))
        print("\tBoot Priority: %d" % chrome_priority)

def parse_part(dat):
    part_type_guid = dat[:16]
    part_guid = dat[16:32]
    first_lba = dat[32:40]
    last_lba = dat[40:48]
    flags = dat[48:56]
    name = dat[56:]
    
    if common.hexify(part_type_guid) == "00000000000000000000000000000000":
        return

    print("Partition Name: \"%s\"" % name.decode("utf-16"))

    print("Partition Type GUID: %s" % parse_guid(part_type_guid))
    print("Partition GUID: %s" % parse_guid(part_guid))
    
    first_lba_unpack = struct.unpack("<q", first_lba)
    print("First LBA: %s" % common.hexify(first_lba_unpack))

    last_lba_unpack = struct.unpack("<q", last_lba)
    print("Last LBA: %s" % common.hexify(last_lba_unpack))

    parse_flags(flags)
    print("\n")

def read_gpt(file_name):
    with open(file_name, 'rb') as f:
        _protected_mbr = f.read(512)  # this should all effectively be junk
        part_header = f.read(512)
        sig = part_header[:8]
        rev = part_header[8:12]
        size = part_header[12:16]
        crc32 = part_header[16:20]
        resrvd = part_header[20:24]
        curr_LBA = part_header[24:32]
        backup_LBA = part_header[32:40]
        first_usable = part_header[40:48]
        last_usable = part_header[48:56]
        disk_guid = part_header[56:72]
        starting_LBA = part_header[72:80]
        num_parts = part_header[80:84]
        part_size = part_header[84:88]
        crc32_part_arr = part_header[88:92]

        ctr = 0
        print("GPT Header (not decoded):\n" + '-'*30)
        for byte in part_header:
            if ctr >= 9:
                print("{} ".format(hex(byte)))
                ctr = 0
            else:
                print("{} ".format(hex(byte)), end="")
                ctr += 1
        print()
        struct.unpack("l", sig)


        print("Partition Signiture: %s" % sig.decode("utf-8"))
        
        print("GPT Revision: %s" % common.hexify(rev))

        size_unpack = struct.unpack("<I", size)
        print("Header Size: %s" % (common.hexify(size_unpack)))    
        
        crc32_unpack = struct.unpack("<I", crc32)
        print("Header CRC32: %s" % common.hexify(crc32_unpack)) 
        
        print("Reserved Chunk: %s" % common.hexify(resrvd))
        
        curr_LBA_unpack = struct.unpack("<q", curr_LBA)
        print("Current LBA: %s" % common.hexify(curr_LBA_unpack))
        
        backup_LBA_unpack = struct.unpack("<q", backup_LBA)
        print("Backup LBA: %s" % common.hexify(backup_LBA_unpack))
        
        first_usable_unpack = struct.unpack("<q", first_usable)
        print("First Usable LBA: %s" % common.hexify(first_usable_unpack))
        
        last_usable_unpack = struct.unpack("<q", last_usable)
        print("Last Usable LBA: %s" % common.hexify(last_usable_unpack))
        print("Disk GUID: %s" % parse_guid(disk_guid))
        
        starting_LBA_unpack = struct.unpack("<q", starting_LBA)
        print("Starting LBA of Partition Entries: %s" % common.hexify(starting_LBA_unpack))
        
        num_parts_unpack = struct.unpack("<I", num_parts)
        print("Number of Partitions: %s" % common.hexify(num_parts_unpack))
        
        part_size_unpack = struct.unpack("<I", part_size)
        print("Partition Data Size: %s" % common.hexify(part_size_unpack))

        crc32_part_arr_unpack = struct.unpack("<I", crc32_part_arr)
        print("Partition Table CRC32: %s\n" % common.hexify(crc32_part_arr_unpack))


        for i in range(num_parts_unpack[0]):
            parse_part(f.read(part_size_unpack[0]))

    # Stuff that isnt working: 
    # UUID parsing not returing correct values, even though 
    # it is all correct allignment for rest of structures
    #
    # Stuff on last partition doesnt seem correct 
    # (Detecting both Windows and Chrome OS)