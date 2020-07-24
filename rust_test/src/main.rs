mod mbr;
mod gpt;

use std::path::Path;
use std::io::prelude::*;
use std::fs::File;


fn main() {

    // get the file paths
    let mbr_path = Path::new("../blackarch_mbr.bin");
    let gpt_path = Path::new("../current_gpt.bin");

    // and pass them to their corresponding parsers
    mbr::load_and_read(&mbr_path);
    gpt::load_and_read(&gpt_path);

}

