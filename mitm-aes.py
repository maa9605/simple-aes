
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

def inverse_mix_columns(state):
        #Inverse mix columns transformation on state matrix
        return [
            gf_mult(9, state[0]) ^ gf_mult(2, state[2]),
            gf_mult(9, state[1]) ^ gf_mult(2, state[3]),
            gf_mult(9, state[2]) ^ gf_mult(2, state[0]),
            gf_mult(9, state[3]) ^ gf_mult(2, state[1]),
        ]
    
def add_round_key(s1, s2):
        #Add round keys in GF(2^4)
        return [i ^ j for i, j in zip(s1, s2)]

def onestep_encrypt(plaintext, key):
   
   state = int_to_state(int(plaintext,2))
   round1 = mix_columns(shift_rows(sub_nibbles(sBox, state)))
   round1 = add_round_key(key, round1)
   encrypted = state_to_int(round1)

   return encrypted

def onestep_decrypt(ciphertext, key):
   
   dstate = int_to_state(int(ciphertext,2))
   dstate = add_round_key(key, dstate)
   dstate = sub_nibbles(sBoxI, shift_rows(dstate))
   decrypted = state_to_int(dstate)
   
   return decrypted

        
def encrypt(plaintext, keys):
   
   state = int_to_state(int(plaintext,2))
   round1 = mix_columns(shift_rows(sub_nibbles(sBox, state)))
   round1 = add_round_key(keys[1], round1)
   round2 = shift_rows(sub_nibbles(sBox, round1))
   round2 = add_round_key(keys[2], round2)
   encrypted = state_to_int(round2)

   return encrypted


def decrypt(ciphertext, keys):
   
   dstate = int_to_state(int(ciphertext,2))
   dstate = add_round_key(keys[2], dstate)
   dstate = sub_nibbles(sBoxI, shift_rows(dstate))
   dstate = inverse_mix_columns(add_round_key(keys[1], dstate))
   dstate = sub_nibbles(sBoxI, shift_rows(dstate))
   decrypted = state_to_int(dstate)
   
   return decrypted


############################### Below is the encryption decryption process in steps ############################
k = 0b1100001111110000  # 16-bit key
ptxt = ["1110001111000111","0111001010011010","1111001011101110","1110111011000111",
        "1011000010100011","1011110000000001","0101001010011101","0010101111011101",
        "1110001111000111","0010011111111110"
       ]
ctxt = ["0010111011001100","0101011011100001","1000101110100111","0010000101001100",
        "1110000010000001","1101111011100110","0111011011100101","0011111010000111",
        "0010111011001100","1100000110111011"
       ]

#create lists of every P+K -> C (for every key there is a ciphertext and a decrypted one)
ptxts = []
ctxts = []


for key in range(65536):
	ptxts.append("{:016b}".format(onestep_encrypt(ptxt[0],int_to_state(key))))
	ctxts.append("{:016b}".format(onestep_decrypt(ctxt[0],int_to_state(key))))

#enumerate thru the plaing text and find where they intersect with ciphertext
for i, j in enumerate(ptxts):
	for x, y in enumerate(ctxts):
	
		#if the 1 round encrypted ciphertext matches the 1 round decrypted plaintext test with 2 P/C pairs
		if j == y:
			keys = [int_to_state(65513), int_to_state(i), int_to_state(x)]
			
			#if the pair produce the expected ciphertext from the key pairs save keys for testing as possible good keys 
			if "{:016b}".format(encrypt(ptxt[1],keys)) == ctxt[1] and "{:016b}".format(encrypt(ptxt[2],keys)) == ctxt[2]:
				print("success:",i,x,)
				skeys = keys
				break
#test good keys
for p, q in enumerate(ptxt):
	if "{:016b}".format(encrypt(ptxt[p],skeys)) == ctxt[p]:
		print("Good Keys", p)

	       
			
		
	   

