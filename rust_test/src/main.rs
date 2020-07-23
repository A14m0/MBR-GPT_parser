extern crate capstone;

use std::fs::File;
use std::fmt;
use std::io::prelude::*;
use std::path::Path;
use std::convert::TryInto;
use byteorder::{BigEndian, ReadBytesExt};

use capstone::prelude::*;


struct MbrPart{
    data: Vec<u8>,
}

impl fmt::Display for MbrPart{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fancy_format_part())
    }
}

impl MbrPart{
    pub fn new(mut chunk: &[u8]) -> Self {
        MbrPart {
            data: chunk.to_vec().clone()
        }
    }

    pub fn fancy_format_part(&self) -> String {
        let mut out = String::new();
    
        for x in self.data.as_slice(){
            out.push_str(format!("0x{:02x} ",x).as_mut_str());
        }
    
        out
    }

    fn hex_helper(&self, dat: &[u8]) -> String{
        let mut out = String::new();

        for x in dat.iter().rev(){
            out.push_str(format!("{:02x}",x).as_mut_str());
        }

        out
    }

    pub fn info(&self) -> String {
        let mut out = String::new();
        let mut tmp_str = String::new();

        let mut tmp_vec = self.data.clone();

        let mut active_part = false;
        if(self.data[0] == 0x80){
            active_part = true;
        } 

        let part_start = &tmp_vec[1..3];
        let part_fs = &tmp_vec[4];
        let part_end = &tmp_vec[5..8];
        let sector_start = &tmp_vec[8..12];
        
        // this no work... y

        let ret: [u8;4] = tmp_vec[12..16].try_into().expect("Incorrect slice length");

        let size = u32::from_le_bytes(ret);

        out.push_str(format!("\tActive partition: {}\n", active_part).as_mut_str());
        out.push_str(format!("\tPartition FS: 0x{:x}\n", part_fs).as_mut_str());
        out.push_str(format!("\tStart Cylinder: 0x{}\n", self.hex_helper(part_start)).as_mut_str());
        out.push_str(format!("\tEnd Cylinder: 0x{}\n", self.hex_helper(part_end)).as_mut_str());
        out.push_str(format!("\tSector Start: 0x{}\n", self.hex_helper(sector_start)).as_mut_str());
        out.push_str(format!("\tPartition Size: 0x{}\n", size).as_mut_str());


        out

    }
}

fn disassemble_mbr_instructions(data: Vec<u8>) -> CsResult<()>{
    let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode16)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()?;
    let insns = cs.disasm_all(data.as_slice(), 0x0)?;
    println!("Found {} instructions", insns.len());

    for i in insns.iter(){
        println!("{}", i);
    }

    Ok(())
}


fn parse_partitions(mut part_table: &[u8]){
    assert_eq!(part_table.len(), (510-446));

    let part_1 = MbrPart::new(&part_table[..16]);
    let part_2 = MbrPart::new(&part_table[16..32]);
    let part_3 = MbrPart::new(&part_table[32..48]);
    let part_4 = MbrPart::new(&part_table[48..]);

    println!("Partition 1: {}", part_1);
    println!("{}", part_1.info());
    
    println!("Partition 2: {}", part_2);
    println!("{}", part_2.info());
    
    println!("Partition 3: {}", part_3);
    println!("{}", part_3.info());
    
    println!("Partition 4: {}", part_4);
    println!("{}", part_4.info());
    
}

fn read_mbr(mut dat: Vec<u8>) {
    //println!("data: {:?}", dat);

    let operations = &dat[0..446];
    let partition_table = &dat[446..510];
    let magic = &dat[510..];

    parse_partitions(partition_table);

    disassemble_mbr_instructions(operations.to_vec());
    
}

fn main() {
    let path = Path::new("../blackarch_mbr.bin");
    let display = path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut v = vec![0; 512];
    let size = match file.read(&mut v) {
        Err(why) => panic!("couldn't read {}: {}", display, why),
        Ok(size) => size,
    };

    read_mbr(v);
    /*if let Err(err) = disassemble_mbr_instructions(text_scn.data.clone()) {
        println!("Error: {}", err);
    }*/
}

