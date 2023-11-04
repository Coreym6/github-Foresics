import re
import hashlib# we will need this for the SHA-256 value

pdf_sig = re.compile(b'\x25\x50\x44\x46')
footer_patterns = [
    b'\x0A\x25\x25\x45\x4F\x46\x0A',
    b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
    b'\x0A\x25\x25\x45\x4F\x46\x0A',
    b'\x0A\x25\x25\x45\x4F\x46'
]
# add in temp_filename variables
pdf_footer_sig = re.compile(b'|'.join(footer_patterns))
#pdf_footer = re.compile(b'\x0A\x25\x25\x45\x4F\x46\x0A')
#b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
#b'\x0A\x25\x25\x45\x4F\x46\x0A',
#b'\x0A\x25\x25\x45\x4F\x46') '''

print("hello world")
def pdf_recov( pdf_sig, pdf_footer_sig):
    # Compile the regex pattern using the header signature

    #changed the pattern to the header of an pdf
    #H = re.compile(header_sig)
    header_to_bytes = pdf_sig.encode('utf-8') 
    footer_to_bytes = pdf_footer_sig.encode('utf-8') # might have to add an encoding if that doesn't work
    #footer_to_bytes = pdf_footer.encode('utf-8')
    #footer_pattern = re.compile(b'\xFF\xD9') # this can be for the footer of the file
    ''' There is multiple footers, here is the file sigs for this ones,
    b'\x0A\x25\x25\x45\x4F\x46\x0A',
        b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
        b'\x0A\x25\x25\x45\x4F\x46\x0A',
        b'\x0A\x25\x25\x45\x4F\x46
        I will likely have to approach it in a similar manner'''
    # Create an empty list to store matched offsets
matched_offsets = []
matched_footer_offsets =[]
# Read the disk image file
with open("Project2.dd", "rb") as file:
    disk_image_data = file.read()


# Search for header pattern and store matched offsets
for match in pdf_sig.finditer(disk_image_data):
    offset = match.start()
    matched_offsets.append(offset)
    print(f"Found header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of matched offsets:", matched_offsets)
#header_offsets = [match.start() for match in header_sig.finditer(disk_image_data)] # this is correct method,open diskimage.dd(head))

matched_footer_offsets =[] # I might have to change this
with open("Project2.dd", "rb") as file:
    disk_image_data2 = file.read()

for match in pdf_footer_sig.finditer(disk_image_data2): 
    pdf_f_offset = match.start()
    matched_footer_offsets.append(pdf_f_offset) # and possibly this to another list
    print(f"Found footer pattern at offset: {pdf_f_offset}")
print("List of matched ending offsets:", matched_footer_offsets)

hash_object = hashlib.sha256(disk_image_data)
hash_object2 = hashlib.sha256(disk_image_data2)
hash_hex = hash_object.hexdigest()
hash_hexf = hash_object2.hexdigest() # added this to test out SHA-256 hashlib
print("SHA-256 Hash of the PDF file:", hash_hex, hash_hexf)
# okay now that we have this information, let's attempt to carve the file.

# Read data between header and footer offsets
'''carved_data = file.read(matched_footer_offsets - matched_offsets + len(pdf_footer_sig.pattern))
#i=1
        # Create a new file to save the carved data
with open(f"recovered_file_{carved_data[:20]}.pdf", "wb") as carved_file:
            carved_file.write(carved_data)'''
#will fix later to the files, we at least got the offsets
# also I need to add SHA-256 Function 

bmp_sig = re.compile(b'\x42\x4D....\x00\x00\x00\x00')# might have to edit this
bmp_footer_sig = re.compile(b'None')
bmp_size = re.compile(77,942) # I'll either have to feed that in or possible the file size
# the file size for the bmp according to the disk editor is 77,942




# start of the bmp file recover
def bmp_recov( bmp_sig):#start of bmp function, will likely have to use file size

    # Compile the regex pattern using the header signature

    #changed the pattern to the header of an pdf
    #H = re.compile(header_sig)
    header_to_bytes = bmp_sig.encode('utf-8') 
    size_to_bytes = bmp_size.encode('utf-8') # might have to add an encoding if that doesn't work
    #footer_to_bytes = pdf_footer.encode('utf-8')
    #footer_pattern = re.compile(b'\xFF\xD9') # this can be for the footer of the file
    ''' There is multiple footers, here is the file sigs for this ones,
    b'\x0A\x25\x25\x45\x4F\x46\x0A',
        b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
        b'\x0A\x25\x25\x45\x4F\x46\x0A',
        b'\x0A\x25\x25\x45\x4F\x46
        I will likely have to approach it in a similar manner'''
    # Create an empty list to store matched offsets
matched_offsets = []
#matched_footer_offsets =[]
# Read the disk image file
with open("Project2.dd", "rb") as file:
    bmp_image_data = file.read()

# Search for header pattern and store matched offsets
for match in bmp_sig.finditer(bmp_image_data):
    offset = match.start()
    matched_offsets.append(offset)
    print(f"Found header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of matched offsets:", matched_offsets)

hash_object = hashlib.sha256(bmp_image_data)
bmp_hex = hash_object.hexdigest()
 # added this to test out SHA-256 hashlib
print("SHA-256 Hash of the BMP file:", bmp_hex)
#header_offsets = [match.start() for match in header_sig.finditer(disk_image_data)] # this is correct method,open diskimage.dd(head))

'''matched_footer_offsets =[] # I might have to change this
with open("Project2.dd", "rb") as file:
    disk_image_data2 = file.read()
# DOES NOT NEED THIS SECTION BECAUSE IT HAS NO FOOTER
for match in bmp_footer_sig.finditer(disk_image_data2): 
    offset = match.start()
    bmp_footer_sig.append(offset) # and possibly this to another list
    print(f"Found footer pattern at offset: {offset}")
print("List of matched ending offsets:", bmp_footer_sig)'''