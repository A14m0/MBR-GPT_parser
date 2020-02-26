#!/usr/bin/env python3
from capstone import *
import mbr
import gpt

#https://medium.com/sector443/python-for-reverse-engineering-1-elf-binaries-e31e92c33732
#http://blog.hakzone.info/posts-and-articles/bios/analysing-the-master-boot-record-mbr-with-a-hex-editor-hex-workshop/




mbr.read_mbr("blackarch_mbr.bin")
print("\n" *4)
gpt.read_gpt("current_gpt.bin")