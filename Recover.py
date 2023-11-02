'''This is a project by ankush Singh and Corey McDaniels 
File types for attempted recovery:
MPG
PDF
BMP
GIF
JPG
DOCX
AVI
PNG
ZIP (since we're graudate students)

Disk image feed in, Project2.dd 
'''
# the imports that we deemed necessary are below
# this can be edited 
import re # used for regex queries
import struct # used to convert hex bytes to long integer
import binascii # used to convert hex strings to bytes
import argparse # parses command line arguments
import hashlib # used to calculate hashes
import sys # used to exit upon error
# additional imports from different file main.py 
import re
import os
import shutil
import sys

'''
import mmap
import sys
import os
import hashlib
import struct
from hashlib import file_digest
'''
# file carver for jpeg, link https://stackoverflow.com/questions/48276658/python-jpeg-file-carver-takes-incredibly-long-on-small-dumps

''' signature feed in; this can be done in multiple ways but either one had an array filled in 
The b, we got from this stack overflow article. 
https://stackoverflow.com/questions/27178366/why-does-bytes5-return-b-x00-x00-x00-x00-x00-instead-of-b-x05
Signature information was taken from https://www.garykessler.net/library/file_sigs.html'''

# this is to add in the different file types that might be added in later.

File_variation = ['PDF','JPG','PNG','GIF','AVI','MPG','BMP','DOCX']
disk = ['Project2.dd']# might have to remove this a little bit later 
print('This is the start of the code')
print("disk = ['Project2.dd']")

file_sigs = { # also recovered 10 out of the 13 files through binwalk commands
    '.pdf': [
        b'\x25\x50\x44\x46',
        b'\x0A\x25\x25\x45\x4F\x46\x0A',
        b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
        b'\x0A\x25\x25\x45\x4F\x46\x0A',
        b'\x0A\x25\x25\x45\x4F\x46'
    ],
    '.jpg': [
        b'\xFF\xD8\xFF\xE0',
        b'\xFF\xD9',
        b'\xFF\xD8\xFF\xE1',
        b'\xFF\xD9',
        b'\xFF\xD8\xFF\xE2',
        b'\xFF\xD9',
        b'\FF\xD8\xFF\xE8',
        b'\xFF\xD9',
        b'\xFF\xD8\xFF\xDB',
        b'\FF\xD9'
    ],
    '.png': [
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
        b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
    ],
    '.gif': [
        b'\x47\x49\x46\x38\x37\x61',
        b'\x00\x00\x3B',
        b'\x47\x49\x46\x38\x39\x61',
        b'\x00\x00\x3B'
    ],
    '.avi': [
    b'\x52\x49\x46\x46....\x41\x56\x49\x20\x4C\x49\x53\x54',
    None # does not have a proper footer either
    ],
    '.mpg': [
        b'\x00\x00\x01\xB3.\x00',
        b'\x00\x00\x00\x01\xB7'
    ],
    '.bmp': [
        b'\x42\x4D....\x00\x00\x00\x00',
        None # because this doesn't have a proper footer 
    ],
    '.docx': [
        b'\x50\x4B\x03\x04\x14\x00\x06\x00',
        b'\x50\x4B\x05\x06'
    ] # no need to worry about the zip file anymore 
}

headers_list =[]
footers_list =[]
# included both for the sake of organization overall 

#def init_
# add method to find the zip of a file 
'''pdf
jpg 
png 
gif 
avi 
mpg 
bmp
docx 
png'''

#def pdf_recov 
#def jpg_recov 
#def png_recov
#def gif_recov
#def avi_recov
#def mpg_recov
#def bmp_recov
#def docx_recov
#def png_recov

def pdf_recov(headers_recov, footers_recov, file_name, file_extension, footer_length, pdf_stream):

    header_count = len(headers_recov)
    footer_count = len(footers_recov)
    
    """
    If no headers found, return.
    """
    if header_count == 0:
        return

    """
    Loop through the header locations
    """
    for index in range(header_count):

        """
        The start of the file is always the current header in the sequence
        """
        file_start = headers_recov[index]

        """
        If not the last header, then the footer for this file
        will be the footer with an offset right after
        the current header since PDF files have one footer per file
        """
        footer_iterator = 0
        while footer_iterator < footer_count and footers_recov[footer_iterator] < headers_recov[index]:
            footer_iterator += 1
        
        if footer_iterator < footer_count:
            file_end = footers_recov[footer_iterator] + footer_length
        else:
            # If no footer found for this header, set the end of the file to the end of the PDF stream.
            file_end = len(pdf_stream)

        """
        Carve bytes out from the PDF stream
        """
        output_name = file_name + '_' + str(index) + '.' + file_extension
        output_data = pdf_stream[file_start:file_end]

        # Write the carved PDF data to a file
        with open(output_name, 'wb') as output_file:
            output_file.write(output_data)

        file_element = get_empty_recovered_element()
        file_element['name'] = output_name
        file_element['start'] = file_start
        file_element['end'] = file_end
        file_element['sha'] = get_sha256(output_name)  # Calculate the SHA-256 hash of the carved file
        recovered_files.append(file_element)
    print('Here is the recovery of the pdf file')


import re

def find_offsets(binary_data, regex_pattern):
    offsets = []
    for match in regex_pattern.finditer(binary_data):
        offsets.append(match.start())
    return offsets

def carve_file(binary_data, offset, output_directory, file_extension, headers):
    if offset in headers:
        return  # Skip offsets that have already been carved

    # Get the contents of the file from the header offset to the end of the file
    file_data = binary_data[offset:]

    # If the file type is a PDF, find the offset of the next header match
    if file_extension == '.pdf':
        next_offset = None
        for match in headers[file_extension].finditer(binary_data[offset + 1:]):
            next_offset = match.start() + offset
            break

        if next_offset is not None:
            file_data = binary_data[offset:next_offset]

    # Create a unique output filename for each carved file
    output_filename = f"{output_directory}/carved_file_{offset}{file_extension}"

    # Write the carved file to a file
    with open(output_filename, 'wb') as output_file:
        output_file.write(file_data)

    # Mark this offset as carved
    headers.add(offset)

    print(f"Carved {file_extension} file saved as: {output_filename}")

# List of file types and their header regex patterns
signatures = {
    '.pdf': re.compile(b'%PDF-\\d\.\\d'),
    '.avi': re.compile(b'\x52\x49\x46\x46'),
    # Add other file types and their regex patterns as needed
}

# Example usage:
output_directory = "carved_files"
binary_data = b"..."  # Replace with your binary data

# Initialize a set to keep track of carved headers
carved_headers = set()

for file_extension, header_pattern in signatures.items():
    header_offsets = find_offsets(binary_data, header_pattern)

    for offset in header_offsets:
        carve_file(binary_data, offset, output_directory, file_extension, carved_headers)




''' print("\nFile Name: " + name)
                print("Starting Offset: " + hex(offset))
                print("End Offset: " + hex(end))
                print("SHA-256 Hash: " + file_hash)
potential print function 
'''






"""
we got this code from consulting another source
https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
also here is a proof of implementation of it:
https://github.com/zleggett/FileRecovery/blob/main/FileRecovery.py
This can prove to be useful for the hash function. 
Also this is for the SHA-256 hash function 
import hashlib
Buff_size = 65
inputFile = raw_input("Enter the name of the file:")
openedFile = open(inputFile)
readFile = openedFile.read()

md5Hash = hashlib.md5(readFile)
md5Hashed = md5Hash.hexdigest()

sha1Hash = hashlib.sha1(readFile)
sha1Hashed = sha1Hash.hexdigest()

print "File Name: %s" % inputFile
print "MD5: %r" % md5Hashed
print "SHA1: %r" % sha1Hashed"""