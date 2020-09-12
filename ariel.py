from Crypto.Cipher import AES

BYTE_SIZE = 8
BINARY_BLOCK_SIZE = 16
BLOCK_HEX_SIZE = BINARY_BLOCK_SIZE * 2


def get_iv_cipher(cipher):
    '''
    Ease the operation of spliting the cipher to iv and cipher.+
    :param cipher: iv + cipher.
    :return: tuple of iv and cipher
    '''
    # Convert the data to hexdecimal - not necessary but I had rough time with binary.
    cipher = cipher.hex()
    # Split the text in hex size.
    iv, cipher = bytes.fromhex(cipher[:BLOCK_HEX_SIZE]), bytes.fromhex("".join(cipher[BLOCK_HEX_SIZE:]))
    return iv, cipher


def xor_byte_arrays(first, second):
    '''
    Create xor operation on both arrays.
    :param first: first byte array.
    :param second: second byte array.
    :return: the xor result of both of them.
    '''
    # Check for bad input.
    assert (len(first) == len(second))
    # Xor each char.
    for i in range(len(first)):
        first[i] ^= second[i]
    # Return the result of the two arrays.
    return first


def cbc_custom_decrypt(k, n, cipher):
    '''
    Decrypt user input.
    :param k: key
    :param n: never used.
    :param cipher: iv + chiper
    :return: plain text after decryption of chiper.
    '''
    cipher_blocks = [cipher[i:i + BINARY_BLOCK_SIZE] for i in range(0, len(cipher), BINARY_BLOCK_SIZE)]
    plain_text = bytearray()
    # Creating new cbc decrypter.
    aes = AES.new(k, AES.MODE_ECB)
    for i in range(n):
        # Asking from the chain decrypter to decrypt our cipher from the user.
        decrypted_block_cipher = bytearray(aes.decrypt(cipher_blocks[i + 1]))
        # Converting our bytes to bytes array for better feeling in hand.
        iv = bytearray(cipher_blocks[i])
        # Adding each xor result to our empty bytes array.
        plain_text += xor_byte_arrays(decrypted_block_cipher, iv)
    return plain_text


def find_flipped_block(blocks):
    '''
    Find the block index where the bit flipped.
    :param blocks: list of 16 bytes.
    :return: the index of the block where not all the bytes are equals.
    '''
    # For each block of chiper we would like to check if each byte is equal to the first byte.
    for index, block in enumerate(blocks):
        result = all(elem == block[0] for elem in block)
        if not result:
            return index


def find_flipped_bit(block):
    '''
    Finding the flipped bit by looking for the only byte that occured only once in the cipher text.
    And then xoring him with the common byte ( all other bytes except our odd byte are equals ) - to find the bit.
    :param block: the block where the block before him changed the bit.
    :return: the index where the bit flipped - reading from right to left.
    '''
    # Getting the byte index which is not equals to rest of the bytes due to the flip of bit in the block before.
    flipped_byte_index = [index for index, element in enumerate(block) if block.count(element) == 1][0]
    # Getting the common byte to compare afterwards with the odd byte.
    common_byte = block[0] if flipped_byte_index != 0 else block[1]
    # Getting the odd byte using the index we found before.
    odd_byte = block[flipped_byte_index]
    # Losing the 0b of binary numbers in python. - Utils
    odd_byte = '{0:08b}'.format(odd_byte)
    common_byte = '{0:08b}'.format(common_byte)
    # Finding the index where the two nubers are not equals.
    flipped_bit_index = [index for index, _ in enumerate(common_byte) if common_byte[index] != odd_byte[index]][0] + 1
    # Reading from right to left ( lsb is index number 0 and msb is index number 7 ) and adding everything to the right
    # block index ( which we found before we entered the function ).
    return flipped_byte_index, BYTE_SIZE - flipped_bit_index


def cbc_flip_fix(key, n, cipher):
    '''
    Finding the flipped bit and changing it back.
    :param key: key
    :param n: never used.
    :param cipher: iv + cipher
    :return: return the plain text without bits flipped.
    '''
    # Creating new aes to show that the flipped bit made chaos in our plain text.
    plain_text = cbc_custom_decrypt(key, n, cipher)
    # Easy way to get iv and cipher from cipher.
    iv, cipher = get_iv_cipher(cipher)
    # Splitting our cipher text to blocks.
    blocks = [plain_text[i: i + BINARY_BLOCK_SIZE] for i in range(0, len(plain_text), BINARY_BLOCK_SIZE)]
    # Finding the block where the bit where changed.
    flipped_block_index = find_flipped_block(blocks)
    # Using the function above we know the index where the bit flipped so we will go to the next block,
    # to find in which specific bit the bit changed.
    flipped_byte_index, flipped_bit_index = find_flipped_bit(blocks[flipped_block_index + 1])
    # After we got the correct block that changed and the correct index where the bit changed we can flip it back.
    flipped_bit = 1 << flipped_bit_index
    # Using byteArray for better operations.
    cipher = bytearray(cipher)
    # Using Xor again to flip back our bad bit.
    cipher[flipped_block_index * BINARY_BLOCK_SIZE + flipped_byte_index] ^= flipped_bit
    # Decrypting again to show the flipping succeeded.
    plain_text = cbc_custom_decrypt(key, n, bytes(iv + cipher))
    return plain_text[flipped_block_index * BINARY_BLOCK_SIZE: (flipped_block_index + 1) * BINARY_BLOCK_SIZE]


# region
# def generate_plain_text():
#     '''
#     Generate 2 - 16 bytes long arrays.
#     :return: return the bytes we would work on.
#     '''
#     return [bytearray(b'\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA'),
#             bytearray(b'\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE')]
# def encrypt_plain_text(key, plain_text, iv):
#     '''
#     Simple as it sounds - we would like to encrypt the data above to test our code.
#     :param key: key
#     :param plain_text: plain text
#     :param iv: iv
#     :return: encrypted data.
#     '''
#     aes = AES.new(key, AES.MODE_CBC, iv)
#     plain_text = plain_text[0] + plain_text[1]
#     cipher = aes.encrypt(bytes(plain_text))
#     # Concat our iv and the cipher to send to our decryption algorithm.
#     cipher = iv + cipher
#     return cipher
#
#
# def flip_bit_in_block_i_index_j(cipher, i, j):
#     '''
#
#     :param cipher: iv + cipher
#     :param n:
#     :param i: block i
#     :param j: bit j
#     :return:
#     '''
#     # Splitting our iv and cihper.
#     iv, cipher = get_iv_cipher(cipher)
#     # Converting to arrays to easier operations like xor.
#     iv = bytearray(iv)
#     cipher = bytearray(cipher)
#     # Flipping bit for testing.
#     cipher[i * BINARY_BLOCK_SIZE + j] ^= 1
#     return bytes(iv + cipher)
# endregion

def main():
    pass


if __name__ == '__main__':
    main()
