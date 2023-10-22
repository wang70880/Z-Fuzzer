seed_file = open('zstack_iar/seedfile', 'wb')

seed_bytes = [
    b'\x07',     # Packet length
    b'\xff\x40\x50\x60\x70\x87',
]

final_bytes = b''
for b in seed_bytes:
    final_bytes += b

seed_file.write(final_bytes)
seed_file.close()