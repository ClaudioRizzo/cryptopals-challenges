import base64
import string
import operator


def hex2b64(hex_str):
    byte_arr = bytearray.fromhex(hex_str)
    return base64.b64encode(byte_arr)


def fixed_xor(hexb1, hexb2):
    buf1 = bytearray.fromhex(hexb1)
    buf2 = bytearray.fromhex(hexb2)

    assert len(buf1) == len(buf2)

    n = len(buf1)

    xored = bytearray()
    for i in range(n):
        xored.append(buf1[i] ^ buf2[i])

    return xored


def crack_single_char_xor(cypher):
    potential_keys = string.ascii_letters

    c_bytes = bytearray.fromhex(cypher)
    results = []
    for pot_key in potential_keys:
        clear_text = bytearray()
        for b in c_bytes:
            clear_text.append(b ^ ord(pot_key))
        #print("Key: {}\n{}\n================".format(pot_key, clear_text.decode('utf-8')))
        results.append(clear_text.decode('utf-8'))

    results = filter(lambda x: x.count('a') > 1, results)
    for res in results:
        print(res)


def rep_xor(key, plain_text):
    key_bytes = bytearray(key, 'utf-8')
    plain_bytes = bytearray(plain_text, 'utf-8')

    key_len = len(key_bytes)

    cypher = bytearray()
    for i in range(len(plain_bytes)):
        b = plain_bytes[i]
        key = key_bytes[i % key_len]
        cypher.append(b ^ key)

    print(bytearray.hex(cypher))


def _byte_array_to_bits(byte_array):
    result = []
    for byte in byte_array:
        bits = bin(byte)[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result


def get_chiper_from_file(path='cipher.b64'):
    with open(path, 'r') as f:
        return base64.b64decode(f.read())


def str_hamming(s1, s2):
    assert len(s1) == len(s2)

    s1_bits = _byte_array_to_bits(bytearray(s1, 'utf-8'))
    s2_bits = _byte_array_to_bits(bytearray(s2, 'utf-8'))

    return bit_hamming(s1_bits, s2_bits)


def bit_hamming(s1_bits, s2_bits):
    assert len(s1_bits) == len(s2_bits)
    return sum(b1 != b2 for b1, b2 in zip(s1_bits, s2_bits))


def guess_key_size(cipher_bytes):
    candidates = {}
    for key_size in range(2, 40):
        chunk_1 = cipher_bytes[:key_size]
        chunk_2 = cipher_bytes[key_size:2*key_size]
        chunk_3 = cipher_bytes[2*key_size:3*key_size]
        chunk_4 = cipher_bytes[4*key_size:5*key_size]

        d1 = bit_hamming(_byte_array_to_bits(chunk_1),
                         _byte_array_to_bits(chunk_2))

        d2 = bit_hamming(_byte_array_to_bits(chunk_3),
                         _byte_array_to_bits(chunk_4))
        d = (d1 + d2) / 2
        candidates[key_size] = d / key_size

    return list(map(lambda x: x[0], sorted(candidates.items(),
                                           key=operator.itemgetter(1))))


def extract_trasnspose_chunks(_bytes, key_size):
    for i in range(key_size):
        block = b''
        for j in range(i, len(_bytes), key_size):
            block += _bytes[j]
        