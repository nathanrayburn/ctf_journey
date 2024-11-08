#PRNG that generates number_bytes pseudo-random bytes
#sedd has to be a random element in Z_n
#n = pq with p, q prime
def bbs(seed, number_bytes, n):
    ret = 0
    for _ in range(number_bytes*8):
        seed = pow(seed, 2, n)
        ret <<= 1
        ret |= (seed % 2)
    return ret.to_bytes(number_bytes), seed


#Encrypts the flag with a stream cipher based on the BBS PRNG. 
#Returns the ciphertext and a masked final state of the PRNG
#new_seed + p is given as rp in the parameters
#new_seed + q is given as rq in the parameters
def hide_flag(seed, n, flag, p, q):
    (random, new_seed) = bbs(seed, len(flag), n)
    return strxor(flag, random), new_seed + p, new_seed + q

