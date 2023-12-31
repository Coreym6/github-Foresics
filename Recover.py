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

#File_variation = ['PDF','JPG','PNG','GIF','AVI','MPG','BMP','DOCX']
#disk = ['Project2.dd']# might have to remove this a little bit later 
headers_list =[]
footers_list =[] 
# included both list for the sake of not having to do an interation for each file, better for organization overall 
print('This is the start of the code')
#print("disk = ['Project2.dd']")

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


# included both for the sake of organization overall 

#def init_
# add method to find the zip of a file 
'''pdf(got this function done)
jpg (got this function done)
png (got this function done)
gif (done with this function)
avi (done)
mpg (done)
bmp
docx 
'''

#def pdf_recov 
#def jpg_recov 
#def png_recov
#def gif_recov
#def avi_recov
#def mpg_recov
#def bmp_recov
#def docx_recov
#def png_recov

# start of the pdf_recovery 
def pdf_recov(meta_pdf, output, headers_list, footers_list): # wouldn't I still have to account for the footer as well. 
    head_comp = re.compile(b'%PDF-\\d\.\\d')# re.compile, use that to find the pattern and sigs, pass that variable
    #H = re.compile(header)
    # read the disk image, then match the patterns 
    #remember to do print function, and put it in the list. 
    # Basically match H to the disk image
    # get the offset value
    #Do the same to the footer 
    #find the footer too
    #footer offset 
    #And then carve the file out 
    Footer_compo = re.compile(b'%%EOF')
# do same for footer 
# find footer in disk
#find header in disk
    header_offsets = [match.start() for match in head_comp.finditer(meta_pdf)] # this is correct method,open diskimage.dd(head))
    index = 0
    while index < len(header_offsets):
        header_offset = header_offsets[index]
        file_start = header_offset
        footer_offset = None

        match = Footer_compo.search(meta_pdf[header_offset:])
        if match:
            footer_offset = match.start() + header_offset

        if footer_offset is not None:
            file_end = footer_offset + 20  # Assuming a 20-byte footer length
        else:
            # If no footer found for this header, set the end of the file to None.
            file_end = None

        if file_end is not None:
            # Carve the PDF file
            meta_pdf = meta_pdf[file_start:file_end]

            # Create a dictionary to store information about the carved PDF file
            pdf_info = {
                'header_offset': header_offset,
                'file_name': f"{output}/recovered{index}.pdf",
                'file_data': meta_pdf
            }

            # Append the dictionary to the header_list
            headers_list.append(pdf_info)

        index += 1

            # Append the dictionary to the header_list
        headers_list.append(pdf_info)

# Example usage:
output = "Project 2/Great_RecoveredFiles"
output2 = "Project 2/Cities_RecoveredFiles"

# Replace pdf_data with your actual PDF data in binary format
meta_pdf = open("Great.pdf", "rb").read()
meta_pdf2 = open("Cities.pdf", "rb").read()
'''footer_data = "This is some footer data"
footer_list.append(footer_data)

# Add more data to the footer list
another_footer_data = "Another piece of footer data"
footer_list.append(another_footer_data)

# The footer_list now contains the added data
print(footer_list)'''
# Already have a list that exist already. 
#header_list = []

pdf_recov(meta_pdf, meta_pdf2, output, headers_list, 'Great')
pdf_recov(meta_pdf, meta_pdf2, output, headers_list, 'Cities')

# Now, header_list contains dictionaries with information about the carved PDF files
for pdf_info in headers_list:
    header_offset = pdf_info['header_offset']
    file_name = pdf_info['file_name']
    file_data = pdf_info['file_data']

    # You can further process or save this information as needed
    print('Here is the recovery of the pdf file')
    print('')    

    # start of the jpg_recovery 
def jpg_recov(meta_jpg, output, headers_list, footers_list): # wouldn't I still have to account for the footer as well. 
    head_comp = re.compile(b'%PDF-\\d\.\\d')
    Footer_compo = re.compile(b'%%EOF')

    header_offsets = [match.start() for match in head_comp.finditer(meta_jpg)]
    index = 0
    while index < len(header_offsets):
        header_offset = header_offsets[index]
        file_start = header_offset
        footer_offset = None

        match = Footer_compo.search(meta_jpg[header_offset:])
        if match:
            footer_offset = match.start() + header_offset

        if footer_offset is not None:
            file_end = footer_offset + 20  # Assuming a 20-byte footer length
        else:
            # If no footer found for this header, set the end of the file to None.
            file_end = None

        if file_end is not None:
            # Carve the PDF file
            meta_jpg = meta_jpg[file_start:file_end]

            # Create a dictionary to store information about the carved PDF file
            jpg_info = {
                'header_offset': header_offset,
                'file_name': f"{output}/recovered{index}.jpg",
                'file_data': meta_jpg
            }

            # Append the dictionary to the header_list
            headers_list.append(jpg_info)

        index += 1

            # Append the dictionary to the header_list
        headers_list.append(jpg_info)

# Example usage:
output = "Project 2/Great_RecoveredFiles"
output2 = "Project 2/Cities_RecoveredFiles"

# Replace pdf_data with your actual PDF data in binary format
meta_jpg = open("Flags.jpg", "rb").read()
meta_jpg2 = open("Iron.jpg", "rb").read()
meta_jpg3 = open("Auburn.jpg", "rb").read()
'''footer_data = "This is some footer data"
footer_list.append(footer_data)

# Add more data to the footer list
another_footer_data = "Another piece of footer data"
footer_list.append(another_footer_data)

# The footer_list now contains the added data
print(footer_list)'''
# Already have a list that exist already. 
#header_list = []

jpg_recov(meta_jpg, meta_pdf2,meta_jpg3,output, headers_list, 'Flags')
jpg_recov(meta_jpg, meta_pdf2,meta_jpg3, output, headers_list, 'Iron')
jpg_recov(meta_jpg, meta_pdf2,meta_jpg3, output, headers_list, 'Auburn')


# Now, header_list contains dictionaries with information about the carved PDF files
for jpg_info in headers_list:
    header_offset = jpg_info['header_offset']
    file_name = jpg_info['file_name']
    file_data = jpg_info['file_data']

    # You can further process or save this information as needed
    print('Here is the recovery of the jpg files')
    print('')
#start of the png recovery function 
def png_recov(meta_png, output, headers_list, footers_list): # wouldn't I still have to account for the footer as well. 
    head_comp = re.compile(b'%PNG-\\d\.\\d')
    Footer_compo = re.compile(b'%%EOF')

    header_offsets = [match.start() for match in head_comp.finditer(meta_png)]
    index = 0
    while index < len(header_offsets):
        header_offset = header_offsets[index]
        file_start = header_offset
        footer_offset = None

        match = Footer_compo.search(meta_png[header_offset:])
        if match:
            footer_offset = match.start() + header_offset

        if footer_offset is not None:
            file_end = footer_offset + 20  # Assuming a 20-byte footer length
        else:
            # If no footer found for this header, set the end of the file to None.
            file_end = None

        if file_end is not None:
            # Carve the PDF file
            meta_png = meta_png[file_start:file_end]

            # Create a dictionary to store information about the carved PDF file
            png_info = {
                'header_offset': header_offset,
                'file_name': f"{output}/recovered{index}.png",
                'file_data': meta_png
            }

            # Append the dictionary to the header_list
            headers_list.append(png_info)

        index += 1

            # Append the dictionary to the header_list
        headers_list.append(png_info)

# Example usage:
output = "Project 2/Dice_RecoveredFiles"

# Replace pdf_data with your actual PDF data in binary format
meta_png = open("Dice.png", "rb").read()


'''footer_data = "This is some footer data"
footer_list.append(footer_data)

# Add more data to the footer list
another_footer_data = "Another piece of footer data"
footer_list.append(another_footer_data)

# The footer_list now contains the added data
print(footer_list)'''
# Already have a list that exist already. 
#header_list = []

png_recov(meta_png, output, headers_list, 'Dice')

# Now, header_list contains dictionaries with information about the carved PDF files
for png_info in headers_list:
    header_offset = png_info['header_offset']
    file_name = png_info['file_name']
    file_data = png_info['file_data']

    # You can further process or save this information as needed
    print('Here is the recovery of the png file')
    print('')  

def gif_recov(meta_gif, output, headers_list, footers_list):
     # wouldn't I still have to account for the footer as well. 
    head_comp = re.compile(b'%Gif-\\d\.\\d')
    # put the footer offset instead
    Footer_compo = re.compile(b'%%EOF')
    re.Match(Footer_compo, file)

    header_offsets = [match.start() for match in head_comp.finditer(meta_gif)]
    index = 0
    while index < len(header_offsets):
        header_offset = header_offsets[index]
        file_start = header_offset
        footer_offset = None

        match = Footer_compo.search(meta_gif[header_offset:])
        if match:
            footer_offset = match.start() + header_offset

        if footer_offset is not None:
            file_end = footer_offset + 20  # Assuming a 20-byte footer length
        else:
            # If no footer found for this header, set the end of the file to None.
            file_end = None

        if file_end is not None:
            # Carve the PDF file
            meta_gif = meta_gif[file_start:file_end]

            # Create a dictionary to store information about the carved PDF file
            gif_info = {
                'header_offset': header_offset,
                'file_name': f"{output}/recovered{index}.gif",
                'file_data': meta_gif
            }

            # Append the dictionary to the header_list
            headers_list.append(gif_info)

        index += 1

            # Append the dictionary to the header_list
        headers_list.append(gif_info)

# Example usage:
output = "Project 2/Minion_RecoveredFiles"
output2 = "Project 2/MandelBrot_RecoveredFiles"

# Replace pdf_data with your actual PDF data in binary format
meta_gif = open("Minion.gif", "rb").read()
meta_gif2 = open("MandelBrot.gif", "rb").read()
'''footer_data = "This is some footer data"
footer_list.append(footer_data)

# Add more data to the footer list
another_footer_data = "Another piece of footer data"
footer_list.append(another_footer_data)

# The footer_list now contains the added data
print(footer_list)'''
# Already have a list that exist already. 
#header_list = []

gif_recov(meta_gif,meta_gif2, output, headers_list, 'Minion')
gif_recov(meta_gif,meta_gif2, output, headers_list, 'MandelBrot')

# Now, header_list contains dictionaries with information about the carved PDF files
for gif_info in headers_list:
    header_offset = gif_info['header_offset']
    file_name = gif_info['file_name']
    file_data = gif_info['file_data']

    # You can further process or save this information as needed
    print('Here is the recovery of the gif file')
    print('')    

# Start of the avi recover function 
def avi_recov(meta_avi, meta_avi2, output, headers_list, footers_list): # wouldn't I still have to account for the footer as well. 
    head_comp = re.compile(b'%AVI-\\d\.\\d')
    Footer_compo = re.compile(b'%%EOF')

    header_offsets = [match.start() for match in head_comp.finditer(meta_avi)]
    index = 0
    while index < len(header_offsets):
        header_offset = header_offsets[index]
        file_start = header_offset
        footer_offset = None

        match = Footer_compo.search(meta_avi[header_offset:])
        if match:
            footer_offset = match.start() + header_offset

        if footer_offset is not None:
            file_end = footer_offset + 20  # Assuming a 20-byte footer length
        else:
            # If no footer found for this header, set the end of the file to None.
            file_end = None

        if file_end is not None:
            # Carve the PDF file
            meta_avi = meta_avi[file_start:file_end]
            sha256_hash = hashlib.sha256(meta_avi).hexdigest() if meta_avi is not None else None
            # Create a dictionary to store information about the carved PDF file
            avi_data = meta_avi[file_start:file_end] if file_end is not None else None
            avi_info = {
                'header_offset': header_offset,
                'file_name': f"{output}/recovered{index}.avi",
                'file_data': meta_avi,
                'sha256_hash': sha256_hash
            }

            # Append the dictionary to the header_list
            headers_list.append(avi_info)

        index += 1

            # Append the dictionary to the header_list
        headers_list.append(avi_info)

# Example usage:
output = "Project 2/Bear_RecoveredFiles"
output2 = "Project 2/Ocean_RecoveredFiles"

# Replace pdf_data with your actual PDF data in binary format
meta_avi = open("Bear.avi", "rb").read()
meta_avi2 = open("Ocean.avi", "rb").read()
'''footer_data = "This is some footer data"
footer_list.append(footer_data)

# Add more data to the footer list
another_footer_data = "Another piece of footer data"
footer_list.append(another_footer_data)

# The footer_list now contains the added data
print(footer_list)'''
# Already have a list that exist already. 
#header_list = []

gif_recov(meta_avi,meta_avi2, output, headers_list, 'Bear')
gif_recov(meta_avi,meta_avi2, output, headers_list, 'Ocean')

# Now, header_list contains dictionaries with information about the carved PDF files
for avi_info in headers_list:
    header_offset = avi_info['header_offset']
    file_name = avi_info['file_name']
    file_data = avi_info['file_data']
    

    # You can further process or save this information as needed
    print('Here is the recovery of the avi files')
    print(f'SHA-256 Hash: {sha256_hash}')
    print('')       

# Start of the bmp recover function 
def mpg_recov(meta_mpg, output, headers_list, footers_list): # wouldn't I still have to account for the footer as well. 
    head_comp = re.compile(b'%BMP-\\d\.\\d')
    Footer_compo = re.compile(b'%%EOF')

    header_offsets = [match.start() for match in head_comp.finditer(meta_mpg)]
    index = 0
    while index < len(header_offsets):
        header_offset = header_offsets[index]
        file_start = header_offset
        footer_offset = None

        match = Footer_compo.search(meta_mpg[header_offset:])
        if match:
            footer_offset = match.start() + header_offset

        if footer_offset is not None:
            file_end = footer_offset + 20  # Assuming a 20-byte footer length
        else:
            # If no footer found for this header, set the end of the file to None.
            file_end = None

        if file_end is not None:
            # Carve the PDF file
            meta_mpg = meta_mpg[file_start:file_end]

            # Create a dictionary to store information about the carved PDF file
            mpg_info = {
                'header_offset': header_offset,
                'file_name': f"{output}/recovered{index}.mpg",
                'file_data': meta_mpg
            }

            # Append the dictionary to the header_list
            headers_list.append(mpg_info)

        index += 1

            # Append the dictionary to the header_list
        headers_list.append(mpg_info)

# Example usage:
output = "Project 2/Universe_RecoveredFiles"


# Replace pdf_data with your actual PDF data in binary format
meta_mpg = open("Universe.mpg", "rb").read()
'''footer_data = "This is some footer data"
footer_list.append(footer_data)

# Add more data to the footer list
another_footer_data = "Another piece of footer data"
footer_list.append(another_footer_data)

# The footer_list now contains the added data
print(footer_list)'''
# Already have a list that exist already. 
#header_list = []

mpg_recov(meta_mpg, output, headers_list, 'Universe')


# Now, header_list contains dictionaries with information about the carved PDF files
for mpg_info in headers_list:
    header_offset = mpg_info['header_offset']
    file_name = mpg_info['file_name']
    file_data = mpg_info['file_data']

    # You can further process or save this information as needed
    print('Here is the recovery of the mpg files')
    print('')       

# Start of the avi recover function 
def bmp_recov(meta_bmp, output, headers_list, footers_list): # wouldn't I still have to account for the footer as well. 
    head_comp = re.compile(b'%BMP-\\d\.\\d')
    Footer_compo = re.compile(b'%%EOF')

    header_offsets = [match.start() for match in head_comp.finditer(meta_bmp)]
    index = 0
    while index < len(header_offsets):
        header_offset = header_offsets[index]
        file_start = header_offset
        footer_offset = None

        match = Footer_compo.search(meta_bmp[header_offset:])
        if match:
            footer_offset = match.start() + header_offset

        if footer_offset is not None:
            file_end = footer_offset + 20  # Assuming a 20-byte footer length
        else:
            # If no footer found for this header, set the end of the file to None.
            file_end = None

        if file_end is not None:
            # Carve the PDF file
            meta_avi = meta_bmp[file_start:file_end]

            # Create a dictionary to store information about the carved PDF file
            bmp_info = {
                'header_offset': header_offset,
                'file_name': f"{output}/recovered{index}.bmp",
                'file_data': meta_bmp
            }

            # Append the dictionary to the header_list
            headers_list.append(bmp_info)

        index += 1

            # Append the dictionary to the header_list
        headers_list.append(bmp_info)

# Example usage:
output = "Project 2/Flower_RecoveredFiles"


# Replace pdf_data with your actual PDF data in binary format
meta_bmp = open("Flower.bmp", "rb").read()
'''footer_data = "This is some footer data"
footer_list.append(footer_data)

# Add more data to the footer list
another_footer_data = "Another piece of footer data"
footer_list.append(another_footer_data)

# The footer_list now contains the added data
print(footer_list)'''
# Already have a list that exist already. 
#header_list = []

gif_recov(meta_bmp, output, headers_list, 'Flower')


# Now, header_list contains dictionaries with information about the carved PDF files
for bmp_info in headers_list:
    header_offset = bmp_info['header_offset']
    file_name = bmp_info['file_name']
    file_data = bmp_info['file_data']

    # You can further process or save this information as needed
    print('Here is the recovery of the bmp files')
    print('')       

    # Start of the docx recover function 
def docx_recov(meta_docx, output, headers_list, footers_list): # wouldn't I still have to account for the footer as well. 
    head_comp = re.compile(b'%DOCX-\\d\.\\d')
    Footer_compo = re.compile(b'%%EOF')

    header_offsets = [match.start() for match in head_comp.finditer(meta_docx)]
    index = 0
    while index < len(header_offsets):
        header_offset = header_offsets[index]
        file_start = header_offset
        footer_offset = None

        match = Footer_compo.search(meta_docx[header_offset:])
        if match:
            footer_offset = match.start() + header_offset

        if footer_offset is not None:
            file_end = footer_offset + 20  # Assuming a 20-byte footer length
        else:
            # If no footer found for this header, set the end of the file to None.
            file_end = None

        if file_end is not None:
            # Carve the PDF file
            meta_docx = meta_docx[file_start:file_end]

            # Create a dictionary to store information about the carved PDF file
            docx_info = {
                'header_offset': header_offset,
                'file_name': f"{output}/recovered{index}.docx",
                'file_data': meta_docx
            }

            # Append the dictionary to the header_list
            headers_list.append(docx_info)

        index += 1

            # Append the dictionary to the header_list
        headers_list.append(docx_info)

# Example usage:
output = "Project 2/Quest_RecoveredFiles"


# Replace pdf_data with your actual PDF data in binary format
meta_docx = open("Quest.docx", "rb").read()
'''footer_data = "This is some footer data"
footer_list.append(footer_data)

# Add more data to the footer list
another_footer_data = "Another piece of footer data"
footer_list.append(another_footer_data)

# The footer_list now contains the added data
print(footer_list)'''
# Already have a list that exist already. 
#header_list = []

docx_recov(meta_docx, output, headers_list, 'Quest')


# Now, header_list contains dictionaries with information about the carved PDF files
for docx_info in headers_list:
    header_offset = docx_info['header_offset']
    file_name = docx_info['file_name']
    file_data = docx_info['file_data']

    # You can further process or save this information as needed
    print('Here is the recovery of the avi files')
    print('')       
''' '''
'''def find_offsets(binary_data, regex_pattern):
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

for file_extension, head_comp in signatures.items():
    header_offsets = find_offsets(binary_data, head_comp)

    for offset in header_offsets:
        carve_file(binary_data, offset, output_directory, file_extension, carved_headers)
'''
''''''


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