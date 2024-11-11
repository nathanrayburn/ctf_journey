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
        state = permutation(state)
    return hash[:output_size]

# You know that the flag length is 19 ASCII characters (including BA{...})
def main():

    hash = b"Jx5FjR7LPlQ1VB/kHmFcBauiE2YvnVVwSvAASA96RCZvmVy855RhvOmtgemhgKWhV5XtFQKx8cIiTUfVSc9qoQ=="
    hash_bytes = b64decode(hash)
    print(len(hash_bytes))
    length_flag = 19 #including BA{...}

main()
