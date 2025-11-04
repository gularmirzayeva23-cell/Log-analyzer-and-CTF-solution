# create_room.py
import os, base64

os.makedirs("server/static/rooms/web-logs-1", exist_ok=True)
p = "server/static/rooms/web-logs-1"

# Exercise 1: file contains THM{...}
ex1_name = "secret_note.txt"
with open(os.path.join(p, ex1_name), "w") as f:
    f.write(
        "This is a random note.\nBut hidden here: THM{this_is_ex1_flag}\nSome other noise.\n"
    )

# Exercise 2: a file contains strings "Yet another" and "Ridiculous acronym"
ex2_name = "readme_notes.txt"
with open(os.path.join(p, ex2_name), "w") as f:
    f.write(
        "Intro text\nYet another line with stuff\nA silly line: Ridiculous acronym inside\nEnd.\n"
    )

# Exercise 3: base64 encoded flag inside a file
flag3 = "THM{This was a really fun exercise}"
b64 = base64.b64encode(flag3.encode()).decode()
ex3_name = "encoded_blob.txt"
with open(os.path.join(p, ex3_name), "w") as f:
    f.write("some header\n")
    f.write(b64 + "\n")
    f.write("footer\n")

# Exercise 4: XOR-encrypted flag: create encrypted hex string and give key only in instructor metadata
flag4 = "THM{FoundSomethingHidden}"
key = 13  # example small integer key
enc = bytes([b ^ key for b in flag4.encode()])
ex4_name = "xor_cipher.txt"
with open(os.path.join(p, ex4_name), "w") as f:
    f.write(enc.hex() + "\n")  # store hex so students must find XOR and decode

# Print to console instructor answers for server config
print("Room files created under server/static/rooms/web-logs-1/")
print("Exercise1 file:", ex1_name, "flag:", "flag{this_is_ex1_flag}")
print("Exercise2 file:", ex2_name, "expected filename:", ex2_name)
print("Exercise3 file:", ex3_name, "contains base64 of flag:", flag3)
print("Exercise4 file:", ex4_name, "encrypted hex (XOR key):", key)
