import re
print("hello world")
def pdf_recov(meta_pdf, output_directory, headers_list, header_sig):
    # Compile the regex pattern using the header signature
    header_pattern = re.compile(b'\x25\x50\x44\x46') #changed the pattern to the header of an pdf 
    footer_pattern = re.compile(b'\xFF\xD9') # this can be for the footer of the file
    # Create an empty list to store matched offsets
matched_offsets = []

# Read the disk image file
with open("Project2.dd", "rb") as file:
    disk_image_data = file.read()

# Search for header pattern and store matched offsets
for match in header_pattern.finditer(disk_image_data):
    offset = match.start()
    matched_offsets.append(offset)
    print(f"Found header pattern at offset: {offset}")

# Print the list of matched offsets
print("List of matched offsets:", matched_offsets)
header_offsets = [match.start() for match in head_comp.finditer(meta_pdf)] # this is correct method,open diskimage.dd(head))
