
def binary_to_ascii(binary_string):
    ascii_string = ""
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        decimal = int(byte, 2)
        ascii_char = chr(decimal)
        ascii_string += ascii_char
    return ascii_string


def main():
    plaintext = "0110111101101011"
    encrypted_message_bin = encryptAES(plaintext)
    decrypted_message_bin = decryptAES(encrypted_message_bin)

    print("Plaintext:", plaintext)

    print("Encrypted message (binary):", encrypted_message_bin)
    print("Decrypted message (binary):", decrypted_message_bin)

    decrypted_message_ascii = binary_to_ascii(decrypted_message_bin)
    print("Decrypted message:", decrypted_message_ascii)

if __name__ == '__main__':
    main()
