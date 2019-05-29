from Crypto.Cipher import AES
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

def get_english_score(input_bytes):
    """Compares each input byte to a character frequency 
    chart and returns the score of a message based on the
    relative frequency the characters occur in the English
    language.
    """

    # From https://en.wikipedia.org/wiki/Letter_frequency
    # with the exception of ' ', which I estimated.
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])


def crack_single_char_xor(cypher):
    '''
    cypher is the hex representation of the bytes composing the chiper text
    '''

    c_bytes = bytearray.fromhex(cypher)
    results = []
    for pot_key in range(256):
        clear_text = bytearray()
        for b in c_bytes:
            clear_text.append(b ^ pot_key)
        score = get_english_score(clear_text)
        data = {
            'text': clear_text,
            'score': score,
            'key': bytes([pot_key])
        }
        results.append(data)
    
    return sorted(results, key=lambda x: x['score'])[-1]

    # results = filter(lambda x: x.count('a') > 1, results)
    


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
    return cypher

def repeating_xor(key_bytes, message_bytes):
    cypher = bytearray()
    for i in range(len(message_bytes)):
        b = message_bytes[i]
        key = key_bytes[i % len(key_bytes)]
        cypher.append(b ^ key)
    return cypher


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

def get_multi_chiper_from_file_hex(path='aeshex'):
    with open(path, 'rb') as f:
        
        return [bytearray.hex(bytearray(line.strip())) for line in f.readlines()]

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
    blocks = []
    for i in range(key_size):
        block = b''
        for j in range(i, len(_bytes), key_size):
            
            block += bytes([_bytes[j]])
        blocks.append(block)
    return blocks


def break_repeating_xor():
    chiper = get_chiper_from_file()
    key_sizes = guess_key_size(chiper)
    
    possible_solutions = []
    for key_size in key_sizes:
        blocks = extract_trasnspose_chunks(chiper, key_size)

        key = b''
        for block in blocks:
            key += crack_single_char_xor(block.hex())['key']

        possible_solutions.append(repeating_xor(key, chiper))
    
    return max(possible_solutions, key=lambda x: get_english_score(x))
    

def decrypt_aes_ecb(chiper, key):
    obj = AES.new(key, AES.MODE_ECB)
    return obj.decrypt(chiper)


def partition_chiper(chiper, bsize):
    return [chiper[i:i+bsize] for i in range(0, len(chiper), bsize)]


def count_repetition_of_blocks(chiper, bsize):
    blocks = partition_chiper(chiper, 16)
    repetitions = len(blocks) - len(set(blocks))
    return (chiper, repetitions)


def is_aes_ecb(chiper, treshold=0):
    '''Given a chiper tells if it was encrypted with ecb.
    treshold is the cutting line for our score.
    
    We split in blocks of 16bytes long and count
    the repetition. If they are more than treshold, we have a hit.
    '''
    return count_repetition_of_blocks(chiper, 16)[1] > treshold

def detect_aes_ecb_among():
    chiphers = get_multi_chiper_from_file_hex()
    repetition_data = []
    for chiper in chiphers:
        c, r = count_repetition_of_blocks(chiper, 16)
        repetition_data.append({'chiper': c, 'rep': r})

    return max(repetition_data, key=lambda x: x['rep'])

print(detect_aes_ecb_among())
