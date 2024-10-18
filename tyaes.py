import time
k = 0b1100001111110000  # 16-bit key

sBox = [0x9,0x4,0xA,0xB,
        0xD,0x1,0x8,0x5,
        0x6,0x2,0x0,0x3,
        0xC,0xE,0xF,0x7]

    # Inverse S-Box
sBoxI = [0xA,0x5,0x9,0xB,
         0x1,0x7,0x8,0xF,
         0x6,0x0,0x2,0x3,
         0xC,0x4,0xD,0xE]

def sub_word(word):
        return (sBox[(word >> 4)] << 4) + sBox[word & 0x0F]

def rot_word(word):
        # Rotate word
        return ((word & 0x0F) << 4) + ((word & 0xF0) >> 4)

def int_to_state(n):
        #Convert a 2-byte integer into a 4-element vector (state matrix)
        return [n >> 12 & 0xF, (n >> 4) & 0xF, (n >> 8) & 0xF, n & 0xF]

def state_to_int(m):
        #Convert a 4-element vector (state matrix) into 2-byte integer
        return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]

def key_expansion(key):

        # Round constants
        Rcon1 = 0x80
        Rcon2 = 0x30

        # Calculating value of each word
        w = [None] * 6
        w[0] = (key & 0xFF00) >> 8
        w[1] = key & 0x00FF
        w[2] = w[0] ^ (sub_word(rot_word(w[1])) ^ Rcon1)
        w[3] = w[2] ^ w[1]
        w[4] = w[2] ^ (sub_word(rot_word(w[3])) ^ Rcon2)
        w[5] = w[4] ^ w[3]

        return (
            int_to_state((w[0] << 8) + w[1]),  # Pre-Round key
            int_to_state((w[2] << 8) + w[3]),  # Round 1 key
            int_to_state((w[4] << 8) + w[5]),  # Round 2 key
        )
        
def gf_mult(a, b):
        #Galois field multiplication of a and b in GF(2^4) / x^4 + x + 1

        product = 0
        # Mask the unwanted bits
        a = a & 0x0F
        b = b & 0x0F
        # While both multiplicands are non-zero
        while a and b:

            # If LSB of b is 1
            if b & 1:

                # Add current a to product
                product = product ^ a

            # Update a to a * 2
            a = a << 1

            # If a overflows beyond 4th bit
            if a & (1 << 4):

                # XOR with irreducible polynomial with high term eliminated
                a = a ^ 0b10011

            # Update b to b // 2
            b = b >> 1

        return product
   
def sub_nibbles(sbox, state):
        #Nibble substitution
        return [sbox[nibble] for nibble in state]

def shift_rows(state):
        #Shift rows and inverse shift rows of state matrix
        return [state[0], state[1], state[3], state[2]]

def mix_columns(state):
        #Mix columns transformation on state matrix
        return [
            state[0] ^ gf_mult(4, state[2]),
            state[1] ^ gf_mult(4, state[3]),
            state[2] ^ gf_mult(4, state[0]),
            state[3] ^ gf_mult(4, state[1]),
        ]
    
def add_round_key(s1, s2):
        #Add round keys in GF(2^4)
        return [i ^ j for i, j in zip(s1, s2)]
        
def encrypt(plaintext):
   
#### NEED TO FIL THIS IN########3

    return encrypted


def decrypt(ciphertext):

#### NEED TO FIL THIS IN########3

    return decrypted


############################### Below is the encryption decryption process in steps ############################

plaintext = "0110111101101011"

#Key Expansion
rnd_keys = key_expansion(k)
print(rnd_keys[0])

#Add Key To Plaintext
plaintext_int = int(plaintext,2)
state = add_round_key(rnd_keys[0], int_to_state(plaintext_int))
round1 = mix_columns(shift_rows(sub_nibbles(sBox, state)))
round1 = add_round_key(rnd_keys[1], round1)
round2 = shift_rows(sub_nibbles(sBox, round1))
round2 = add_round_key(rnd_keys[2], round2)
ciptext = state_to_int(round2)

print(bin(ciptext))
 

