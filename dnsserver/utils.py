def int_to_bytes(value, min_length=1):                                             
    values = []
    while value > 0 or len(values) < min_length:
        values.append(value & 0xFF) 
        value >>= 8
    return bytes(values[::-1])

def bytes_to_int(bytes_):
    i = 0
    for byte in bytes_:
        i <<= 8
        i += int(byte) 
    return i

def display_message_bits(data):
    bits = [bin(data[n])[2:].zfill(8) for n in range(len(data))]
    print('---BEGIN_MESSAGE---')
    print('\n'.join([f'{bits[n]} {bits[n+1]}' for n in range(0, len(bits), 2)]))
    print('---END_MESSAGE--')