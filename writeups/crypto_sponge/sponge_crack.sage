from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

cipher = AES.new(b"\x07"*16, AES.MODE_ECB)
def permutation(b):
    return cipher.encrypt(b)

def pad(message, rate):
    missing = rate - len(message)% rate
    if missing == 0: 
        missing = rate
    message += b"\x80" + b"\x00"*(missing - 1)
    return message 

def sponge(rate, message, output_size):
    #padding
    message = pad(message, rate)
    
    blocks = [message[rate*i:rate*(i+1)] for i in range(len(message)//rate)]
    state = b"\x00"*16
    #absorbing
    for b in blocks:
        state = strxor(state[:rate], b) + state[rate:]
        state = permutation(state)
    #squeezing
    hash  = b""
    while len(hash) < output_size:


        hash += state[:rate]
        print("Hash size : " + str(len(hash)))
        state = permutation(state)
    return hash[:output_size]


def zeroPad(hash, rate):

    current_bits = len(hash) * 8  

    rate_bits = rate * 8
    missing_bits = (rate_bits - current_bits % rate_bits) % rate_bits

    if missing_bits == 0:
        return hash
    

    full_bytes, remaining_bits = divmod(missing_bits, 8)
    
    # Add the byte-level padding (full bytes of 0x00)
    hash += b'\x00' * full_bytes
    
    if remaining_bits > 0:
        last_byte = (1 << (8 - remaining_bits)) - 1  # Create trailing zeros in the last byte
        hash += last_byte.to_bytes(1, byteorder='big')
    
    return hash


def increment_bytes(b):
    # Convert to an integer, increment, and handle overflow
    as_int = int.from_bytes(b, byteorder='big')
    incremented = (as_int + 1) % (1 << (len(b) * 8))  # Wrap around on overflow
    return incremented.to_bytes(len(b), byteorder='big')
    
def bruteforce_ext_state(hash):
    first_ext_state = None
    state_size = 16
    for rate_size in range(state_size - 1, 1, -1):
        capacity_size = state_size - rate_size
        current_rate = hash[:rate_size]
        current_capacity = b'\x00' * capacity_size 
        for i in range((2 ** (capacity_size * 8))):
            print("Iteration: " + str(i) + " Current Bytes Testing: " + str(current_capacity))
            concat = current_rate + current_capacity
            before_perm = zeroPad(concat, state_size)
            if hash[rate_size:rate_size * 2] == permutation(before_perm)[:rate_size]:
                return rate_size, current_rate + current_capacity
            current_capacity = increment_bytes(current_capacity)
    return first_ext_state

import re
import itertools

def bruteforce_inner_state(state,r):
    know_string_start_flag = b'BA24{'  # Known start of the flag
    known_string_end_flag = b"}\x80" + b"\x00" * 10 # end flag + padding
    unknown_bytes = 3
    
    # All possible 3-byte combinations of ASCII characters
    ascii_range = range(32, 127) 
    for guess in itertools.product(ascii_range, repeat=unknown_bytes):
        
        bytes_to_brute_force = bytes(guess)
        
        test_string = bytes_to_brute_force + known_string_end_flag

        guess_state = inverse_function_perm(strxor(state[:r], test_string[:r]) + state[r:])
        
        # Check if we have found the flag
        if guess_state[:r].startswith(know_string_start_flag):
            print("Match found with current bytes:", bytes_to_brute_force)
            return guess_state[:r] + bytes_to_brute_force + known_string_end_flag



    

def inverse_function_perm(b):
    return cipher.decrypt(b)
def unpad(padded_message):
    padding_start_index = padded_message.rfind(b'\x80')
    if padding_start_index == -1:
        return padded_message
    return padded_message[:padding_start_index]

def main():

    hash = b"Jx5FjR7LPlQ1VB/kHmFcBauiE2YvnVVwSvAASA96RCZvmVy855RhvOmtgemhgKWhV5XtFQKx8cIiTUfVSc9qoQ=="
    hash_bytes = b64decode(hash)
    test = b"1234567890123456789"
    print(pad(test,15))
    
    print(len(hash_bytes))
    length_flag = 19 #including BA{...}
    
    r, ext_state = bruteforce_ext_state(hash_bytes) # first external state
    
    print(r)
    print(ext_state)

    if r is not None:
        print("Found Hash Rate")

    flag = bruteforce_inner_state(inverse_function_perm(ext_state),r)
    
    print(unpad(flag))

main()
