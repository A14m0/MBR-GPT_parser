extern crate capstone;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use bit_field::BitArray;


fn get_hex(dat: &[u8]) -> String {
    let mut out = String::new();
    for x in dat.iter(){
        out.push_str(format!("{:x}", x).as_mut_str());
    }
    out
}

fn parse_guid(dat: &[u8]) -> String {
    let mut out = String::new();

    let first = get_hex(&dat[0..4]);
    let second = get_hex(&dat[4..6]);
    let third = get_hex(&dat[6..8]);
    let fourth = get_hex(&dat[8..10]);
    let fifth = get_hex(&dat[10..]);

    out.push_str(format!("{}-{}-{}-{}-{}", first,
                second, third, fourth, fifth).as_mut_str());

    out
}

fn parse_flags(dat: &[u8]){
    assert_eq!(dat.len(), (56-48));
    
    let mut is_windows_part = false;
    let mut is_chrome_part = false;
    let mut rsrv_bits = Vec::new();
    let mut chrome_retries = Vec::new();
    let mut chrome_priority = 0;

    
    // parse flags
    let platform_req = dat.get_bit(0);
    let efi_ign = dat.get_bit(1);
    let legacy_bootable = dat.get_bit(2);
    let read_only = dat.get_bit(60);
    let shadow = dat.get_bit(61);
    let hidden = dat.get_bit(62);
    let no_drive_letter = dat.get_bit(63);
    let successful_boot = dat.get_bit(56);

    if read_only | shadow | hidden | no_drive_letter{
        is_windows_part = true;
    }

    for i in (3..55){
        if dat.get_bit(i){
            rsrv_bits.push(i as u32);
            if i > 47 && i < 56 {
                if is_windows_part{
                    panic!("Detected both Chrome OS and Windows Partitions");
                } else {
                    is_chrome_part = true;
                }
                if i > 52{
                    chrome_retries.push(i as u32);
                } else {
                    chrome_priority = i - 48;
                }

            }

        }
    }

    println!("Flags:\nPlatform Required: {}\nEFI Ignore: {}",
            platform_req, efi_ign);
    println!("Legacy BIOS Bootable: {}\nReserved bits used: {:?}",
            legacy_bootable, rsrv_bits);
    if is_windows_part{
        println!("Detected Windows Partition (from flags)");
        println!("Read-Only: {}\nShadow Copy: {}, Hidden Drive: {}",
                read_only, shadow, hidden);
        println!("No Drive Letter (no automount): {}", no_drive_letter);
    } else if is_chrome_part {
        println!("Detected Chrome OS Partition (from flags)");
        println!("Successful Boot: {}\nTries remaining: {:?}\nBoot Priority: {}",
                successful_boot, chrome_retries, chrome_priority);
    }

}

/// unpacks an integer from bytes
fn unpack_int(bytes: &[u8]) -> u32{
    let mut out = 0u32;
    let mut byte_shifts = 24;
    println!("Unpacking integer: {:?}", bytes);
    for i in 0..4{
        println!("Byte {}", (bytes[i] as u32) << byte_shifts);
        out = out.wrapping_add((bytes[i] as u32) << byte_shifts);
        byte_shifts = byte_shifts - 8;
    }

    println!("Unpacked data: {}", out);
    out
}

/// unpacks long long integer from bytes
fn unpack_long_long(bytes: &[u8]) -> u64 {
    let mut out = 0u64;
    let mut byte_shifts = 48;
    for i in 0..8{
        out = out.wrapping_add((bytes[i] as u64) << byte_shifts);
        byte_shifts = byte_shifts - 8;
    }

    out
}

/// Parse partiton data contained in `data`
fn parse_partition(data: Vec<u8>){

    // parse the data
    let part_type_guid = parse_guid(&data[0..16]);
    let part_guid = parse_guid(&data[16..32]);
    let first_lba = get_hex(&data[32..40]);
    let last_lba = get_hex(&data[40..48]);
    let name = String::from_utf8(data[56..].to_vec()).unwrap();

    // check if empty partition
    if unpack_int(&data[0..16]) == 0u32{
        return;
    }

    // print data
    println!("Partition name: \"{}\"", name);
    println!("Partiton Type GUID: {}", part_type_guid);
    println!("Partition GUID: {}", part_guid);
    println!("First LBA: {}", first_lba);
    println!("Last LBA: {}", last_lba);

    // parse the flags for the partition
    parse_flags(&data[48..56]);
}

/// Read GPT header data
fn read_data(dat: &Vec<u8>, mut file: File){
    let _protected_mbr = &dat[0..512];
    let part_header = dat[512..1024].to_vec();

    // parse the disk's signature into a UTF-8 string
    let sig = match String::from_utf8(part_header[0..8].to_vec()){
        Err(e) => panic!("Failed to convert partition signature to string: {}", e),
        Ok(st) => st
    };

    // get the hex of all of the different things
    let rev = get_hex(&part_header[8..12]); // Parse GPT revision 
    let size = unpack_int(&part_header[12..16]); // parse GPT header size
    let crc32 = get_hex(&part_header[16..20]); // GPT header CRC32 checksum
    let reserved = get_hex(&part_header[20..24]); // Reserved chunk
    let current_lba = get_hex(&part_header[24..32]); // Current Logical Block Address
    let backup_lba = get_hex(&part_header[32..40]); // Backup Logical Block Address
    let first_usable = get_hex(&part_header[40..48]); // First usable sector
    let last_usable = get_hex(&part_header[48..56]); // Last usable sector
    let disk_guid = parse_guid(&part_header[56..72]); // Disk's GUID
    let starting_lba = get_hex(&part_header[72..80]); // Starting Logical Block Address
    let num_parts = unpack_int(&part_header[80..84]); // Number of partitions in table
    let part_size = unpack_int(&part_header[84..88]); // partition data size
    let crc32_part_arr = get_hex(&part_header[88..92]); // Partition table's CRC32

    // print the data
    println!("Partition Signiture: {}", sig);
    println!("GPT Revision: {}", rev);
    println!("Table CRC32: {}", crc32);
    println!("Reserved chunk: {}", reserved);
    println!("Current LBA: {}", current_lba);
    println!("Backup LBA: {}", backup_lba);
    println!("First usable sector: {}", first_usable);
    println!("Last usable sector: {}", last_usable);
    println!("Disk GUID: {}", disk_guid);
    println!("Starting LBA: {}", starting_lba);
    println!("Partition data size: {}", part_size);
    println!("Partition table CRC32: {}", crc32_part_arr);

    // loop over each partition and read its data
    for i in 0..num_parts {
        let mut part_data = vec![0; part_size as usize];
        file.read_exact(part_data.as_mut_slice()).unwrap();
        parse_partition(part_data);
    }

}

pub fn load_and_read(path: &Path){
    // Open the file from `path`
    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", path.display(), why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut v = vec![0; 1024];
    match file.read(&mut v) {
        Err(why) => panic!("couldn't read {}: {}", path.display(), why),
        Ok(size) => size,
    };

    read_data(&v, file)

}