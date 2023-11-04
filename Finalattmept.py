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

print("hello world") # test statment 
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
    print(f"Found pdf header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of matched pdf offsets:", matched_offsets)
#header_offsets = [match.start() for match in header_sig.finditer(disk_image_data)] # this is correct method,open diskimage.dd(head))

matched_footer_offsets =[] # I might have to change this
with open("Project2.dd", "rb") as file:
    disk_image_data2 = file.read()

for match in pdf_footer_sig.finditer(disk_image_data2): 
    pdf_f_offset = match.start()
    matched_footer_offsets.append(pdf_f_offset) # and possibly this to another list
    print(f"Found pdf footer pattern at offset: {pdf_f_offset}")
print("List of matched pdf ending offsets:", matched_footer_offsets)

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

bmp_sig = re.compile(b'\x42\x4D')# might have to edit this
bmp_footer_sig = re.compile(b'None')
bmp_size = re.compile(b'77,942') # I'll either have to feed that in or possible the file size
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
    print(f"Found bmp header pattern at offset: {offset}")

'''for offset in matched_offsets:
        header_data = bmp_image_data[offset:offset + 10]
# Check if the header starts with "BM" (42 4D in hexadecimal)
        if header_data[:2] == b'BM':
            # Extract the 4-byte file size (little-endian)
            file_size = int.from_bytes(bmp_image_data[2:6], byteorder='little')
            print(f"BMP File Size at offset {offset}: {file_size} bytes")
        else:
            print(f"No valid BMP header at offset {offset}")
# Print the list of matched offsets
#print("List of matched offsets:", matched_offsets)'''

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

jpg_header_patterns = [
    b'\xFF\xD8\xFF\xE0',
    b'\xFF\xD8\xFF\xE1',
    b'\xFF\xD8\xFF\xE2',
    b'\xFF\xD8\xFF\xE8',
    b'\xFF\xD8\xFF\xDB'
] # more of the opposite of pdf with multiple footer sigs 
jpg_footer_sig = re.compile(b'\xFF\xD9')

# add in temp_filename variables
jpg_header_sig = re.compile(b'|'.join(jpg_header_patterns))

def jpg_recov( jpg_footer_sig, jpg_header_sig):
    # Compile the regex pattern using the header signature

    #changed the pattern to the header of an pdf
    #H = re.compile(header_sig)
    header_to_bytes = jpg_header_sig.encode('utf-8') 
    footer_to_bytes = jpg_footer_sig.encode('utf-8') # might have to add an encoding if that doesn't work
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
    jpg_image_data = file.read()


# Search for header pattern and store matched offsets
for match in jpg_header_sig.finditer(jpg_image_data):
    offset = match.start()
    matched_offsets.append(offset)
    print(f"Found jpg header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of matched jpg header offsets:", matched_offsets)
#header_offsets = [match.start() for match in header_sig.finditer(disk_image_data)] # this is correct method,open diskimage.dd(head))

matched_footer_offsets =[] # I might have to change this
with open("Project2.dd", "rb") as file:
    jpg_image_data2 = file.read()

for match in jpg_footer_sig.finditer(jpg_image_data2): 
    jpg_f_offset = match.start()
    matched_footer_offsets.append(jpg_f_offset) # and possibly this to another list
    print(f"Found jpg footer pattern at offset: {jpg_f_offset}")
print("List of matched jpg ending offsets:", matched_footer_offsets)

hash_object = hashlib.sha256(jpg_image_data)
hash_object2 = hashlib.sha256(jpg_image_data2)
hash_hex = hash_object.hexdigest()
hash_hexf = hash_object2.hexdigest() # added this to test out SHA-256 hashlib
print("SHA-256 Hash of the JPG file:", hash_hex, hash_hexf)



# START OF PNG RECOVERY FUNCTION 

png_header_sig = re.compile(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A')
png_footer_sig = re.compile(b'\x49\x45\x4E\x44\xAE\x42\x60\x82')

def png_recov( png_footer_sig, png_header_sig):
    # Compile the regex pattern using the header signature

    #changed the pattern to the header of an pdf
    #H = re.compile(header_sig)
    header_to_bytes = png_header_sig.encode('utf-8') 
    footer_to_bytes = png_footer_sig.encode('utf-8') # might have to add an encoding if that doesn't work
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
    png_image_data = file.read()


# Search for header pattern and store matched offsets
for match in png_header_sig.finditer(png_image_data):
    offset = match.start()
    matched_offsets.append(offset)
    print(f"Found png header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of png header matched offsets:", matched_offsets)
#header_offsets = [match.start() for match in header_sig.finditer(disk_image_data)] # this is correct method,open diskimage.dd(head))

matched_footer_offsets =[] # I might have to change this
with open("Project2.dd", "rb") as file:
    png_image_data2 = file.read()

for match in png_footer_sig.finditer(png_image_data2): 
    png_f_offset = match.start()
    matched_footer_offsets.append(png_f_offset) # and possibly this to another list
    print(f"Found png footer pattern at offset: {png_f_offset}")
print("List of matched png ending offsets:", matched_footer_offsets)

hash_object = hashlib.sha256(png_image_data)
hash_object2 = hashlib.sha256(png_image_data2)
hash_hex = hash_object.hexdigest()
hash_hexf = hash_object2.hexdigest() # added this to test out SHA-256 hashlib
print("SHA-256 Hash of the png file:", hash_hex, hash_hexf)




# START OF GIF RECOVERY FUNCTION
gif_header_patterns = [
    b'\x47\x49\x46\x38\x37\x61',
    b'\x47\x49\x46\x38\x39\x61',
] # more of the opposite of pdf with multiple footer sigs 

# add in temp_filename variables
gif_header_sig = re.compile(b'|'.join(gif_header_patterns))

# START OF GIF RECOVERY FUNCTION

gif_footer_sig = re.compile(b'\x00\x00\x3B')

def gif_recov( gif_footer_sig, gif_header_sig):
    # Compile the regex pattern using the header signature

    #changed the pattern to the header of an pdf
    #H = re.compile(header_sig)
    header_to_bytes = gif_header_sig.encode('utf-8') 
    footer_to_bytes = gif_footer_sig.encode('utf-8') # might have to add an encoding if that doesn't work
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
    gif_image_data = file.read()


# Search for header pattern and store matched offsets
for match in gif_header_sig.finditer(gif_image_data):
    offset = match.start()
    matched_offsets.append(offset)
    print(f"Found gif header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of gif header matched offsets:", matched_offsets)
#header_offsets = [match.start() for match in header_sig.finditer(disk_image_data)] # this is correct method,open diskimage.dd(head))

matched_footer_offsets =[] # I might have to change this
with open("Project2.dd", "rb") as file:
    gif_image_data2 = file.read()

for match in gif_footer_sig.finditer(gif_image_data2): 
    gif_f_offset = match.start()
    matched_footer_offsets.append(gif_f_offset) # and possibly this to another list
    print(f"Found gif footer pattern at offset: {gif_f_offset}")
print("List of matched gif ending offsets:", matched_footer_offsets)

hash_object = hashlib.sha256(gif_image_data)
hash_object2 = hashlib.sha256(gif_image_data2)
hash_hex = hash_object.hexdigest()
hash_hexf = hash_object2.hexdigest() # added this to test out SHA-256 hashlib
print("SHA-256 Hash of the gif file:", hash_hex, hash_hexf)




# START OF MPG FILE RECOVERY 

mpg_header_sig = re.compile(b'\x00\x00\x01\xB3.\x00')

   # more of the opposite of pdf with multiple footer sigs 

# add in temp_filename variables

# START OF GIF RECOVERY FUNCTION

mpg_footer_sig = re.compile(b'\x00\x00\x00\x01\xB7')

def mpg_recov( mpg_footer_sig, mpg_header_sig):
    # Compile the regex pattern using the header signature

    #changed the pattern to the header of an pdf
    #H = re.compile(header_sig)
    header_to_bytes = mpg_header_sig.encode('utf-8') 
    footer_to_bytes = mpg_footer_sig.encode('utf-8') # might have to add an encoding if that doesn't work
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
    mpg_image_data = file.read()


# Search for header pattern and store matched offsets
for match in mpg_header_sig.finditer(mpg_image_data):
    offset = match.start()
    matched_offsets.append(offset)
    print(f"Found mpg header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of mpg header matched offsets:", matched_offsets)
#header_offsets = [match.start() for match in header_sig.finditer(disk_image_data)] # this is correct method,open diskimage.dd(head))

matched_footer_offsets =[] # I might have to change this
with open("Project2.dd", "rb") as file:
    mpg_image_data2 = file.read()

for match in mpg_footer_sig.finditer(mpg_image_data2): 
    mpg_f_offset = match.start()
    matched_footer_offsets.append(mpg_f_offset) # and possibly this to another list
    print(f"Found mpg footer pattern at offset: {mpg_f_offset}")
print("List of matched mpg ending offsets:", matched_footer_offsets)

hash_object = hashlib.sha256(mpg_image_data)
hash_object2 = hashlib.sha256(mpg_image_data2)
hash_hex = hash_object.hexdigest()
hash_hexf = hash_object2.hexdigest() # added this to test out SHA-256 hashlib
print("SHA-256 Hash of the mpg file:", hash_hex, hash_hexf)





#start of DOCX recovery file 

# START OF MPG FILE RECOVERY  Function

docx_header_sig = re.compile(b'\x50\x4B\x03\x04\x14\x00\x06\x00')

   # more of the opposite of pdf with multiple footer sigs 

# add in temp_filename variables

docx_footer_sig = re.compile(b'\x50\x4B\x05\x06')

def docx_recov( docx_footer_sig, docx_header_sig):
    # Compile the regex pattern using the header signature

    #changed the pattern to the header of an pdf
    #H = re.compile(header_sig)
    header_to_bytes = docx_header_sig.encode('utf-8') 
    footer_to_bytes = docx_footer_sig.encode('utf-8') # might have to add an encoding if that doesn't work
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
    docx_image_data = file.read()


# Search for header pattern and store matched offsets
for match in docx_header_sig.finditer(docx_image_data):
    offset = match.start()
    matched_offsets.append(offset)
    print(f"Found docx header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of docx header matched offsets:", matched_offsets)
#header_offsets = [match.start() for match in header_sig.finditer(disk_image_data)] # this is correct method,open diskimage.dd(head))

matched_footer_offsets =[] # I might have to change this
with open("Project2.dd", "rb") as file:
    docx_image_data2 = file.read()

for match in docx_footer_sig.finditer(docx_image_data2): 
    docx_f_offset = match.start()
    matched_footer_offsets.append(docx_f_offset) # and possibly this to another list
    print(f"Found docx footer pattern at offset: {docx_f_offset}")
print("List of matched docx ending offsets:", matched_footer_offsets)

hash_object = hashlib.sha256(docx_image_data)
hash_object2 = hashlib.sha256(docx_image_data2)
hash_hex = hash_object.hexdigest()
hash_hexf = hash_object2.hexdigest() # added this to test out SHA-256 hashlib
print("SHA-256 Hash of the docx file:", hash_hex, hash_hexf)