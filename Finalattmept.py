import re

pdf_sig = re.compile(b'\x25\x50\x44\x46')
footer_patterns = [
    b'\x0A\x25\x25\x45\x4F\x46\x0A',
    b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
    b'\x0A\x25\x25\x45\x4F\x46\x0A',
    b'\x0A\x25\x25\x45\x4F\x46'
]

pdf_footer_sig = re.compile(b'|'.join(footer_patterns))
#pdf_footer = re.compile(b'\x0A\x25\x25\x45\x4F\x46\x0A')
#b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
#b'\x0A\x25\x25\x45\x4F\x46\x0A',
#b'\x0A\x25\x25\x45\x4F\x46') '''

print("hello world")
def pdf_recov(meta_pdf, output_directory, headers_list, pdf_sig, pdf_footer):
    # Compile the regex pattern using the header signature

    #changed the pattern to the header of an pdf
    #H = re.compile(header_sig)
    header_to_bytes = pdf_sig.encode('utf-8') 
    footer_to_bytes = pdf_footer_sig # might have to add an encoding if that doesn't work
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

for match in pdf_sig.finditer(disk_image_data):
    offset = match.start()
    matched_footer_offsets.append(offset) # and possibly this to another list
    print(f"Found footer pattern at offset: {offset}")
print("List of matched ending offsets:", matched_footer_offsets)



