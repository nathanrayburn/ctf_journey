# Nathan Rayburn
# BBS CTF Blackalps
import math
from base64 import b64decode
from Crypto.Util.strxor import strxor
from sage.all import Integer, crt, power_mod, mod

# PRNG that generates number_bytes pseudo-random bytes
def bbs(seed, number_bytes, n):
    ret = 0
    for _ in range(number_bytes * 8):
        seed = pow(seed, 2, n)
        ret <<= 1
        ret |= (seed % 2)
    return ret.to_bytes(number_bytes, 'big'), seed

# Function to reverse the BBS and retrieve the original seed
def reverse_bbs(final_seed,p,q):
    current_state = final_seed
    #Fp = Integers(p)
    #Fq = Integers(q)
    for i in range(31*8):

        #root_seed_p = Fp(current_state).sqrt().lift()
        #root_seed_q = Fq(current_state).sqrt().lift()
        root_seed_p = power_mod(current_state, (p+1)/4, p)
        root_seed_q = power_mod(current_state, (q+1)/4, q)
        current_state = crt([root_seed_p,root_seed_q],[p,q])
        
    
    return current_state

#Encrypts the flag with a stream cipher based on the BBS PRNG. 
#Returns the ciphertext and a masked final state of the PRNG
#new_seed + p is given as rp in the parameters
#new_seed + q is given as rq in the parameters
def hide_flag(seed, n, flag, p, q):
    (random, new_seed) = bbs(seed, len(flag), n)
    return strxor(flag, random), new_seed + p, new_seed + q

def find_p_q(n, rp, rq):
    d = rp - rq
    discriminant = d**2 + 4 * n
    sqrt_discriminant = math.isqrt(discriminant)
    
    if sqrt_discriminant * sqrt_discriminant != discriminant:
        raise ValueError("Discriminant is not a perfect square, cannot find integer solution for q")
    
    q1 = (-d + sqrt_discriminant) // 2
    q2 = (-d - sqrt_discriminant) // 2
    p1 = q1 + d
    p2 = q2 + d
    
    if p1 * q1 == n:
        return p1, q1
    elif p2 * q2 == n:
        return p2, q2
    else:
        raise ValueError("Failed to find factors p and q")

# Function to reverse the encryption and retrieve the original flag
def reverse_hide_flag(ct, rp, rq, n, p, q):
    final_state = rp - p if rp - p == rq - q else None
    if final_state is None:
        raise ValueError("Cannot determine the initial seed")


    reversed_seed = reverse_bbs(final_state, p, q)
    random, _ = bbs(reversed_seed,len(ct),n)
    
    return strxor(random,ct)

def main():
    n = 2878722943242584369487577709674021473361830051453027816222804069858926659637346489807660154713889512285202934429001936267583473898531401325035139081590347904842058221685484378041564611477585984431622907947108588828302518036113732770729622949515878791111211973359801381541663020813018610329103958348485213471145209293006150761531986811559187488891892251149531888050169292545509771545640667324151828599863456305492879256014602427873006312859290462892295761185955854271796551785280865032525949062613335214776115714307573221830081083866338378146259997997158901638391839800506491658631375803111197850961542067922747893753
    ct = b'8dVrSQamPxjmsklL1MzoiGvfHGNzFhU3N7T4Dqc+EA=='
    ct_decode = b64decode(ct)
    
    rp = 1880973399310866294973939337139366236280606084465082017500958859540154610474303394665773548131061331306856359141133545841512502267010055611606065595538461387486410529787373541155497233953832913396509173565177246874399830311110462707707083418823381208538109019326703842038778528140208889070332780513599527745513611286879434133486374904668474064774645039651656018580449522288883898075833258166867255223583859866508243969092579819797784337358168208922852255459744396370909138633191133871209019190547729841922128800765621698401230805904360046386756248909424240718256447212405321076152174562243046584207286797104962025680
    rq = 1880973399310866294973939337139366236280606084465082017500958859540154610474303394665773548131061331306856359141133545841512502267010055611606065595538461387486410529787373541155497233953832913396509173565177246874399830311110462707707083418823381208538109019326703842038778528140208889070332780513599527745591780359433604245373333086643705353258723939167850036404956343218409923582973520468795798007883560508899671451178772482057353801336512768263509824877983298297714585947245753148744515883480369205239179338102393395097379899519686099702579092394205849874259514992119325716549057790193361637643092564972333290568

    p, q = find_p_q(n, rp, rq)
    flag = reverse_hide_flag(ct_decode, rp, rq, n, p, q)

    try:
        flag_str = flag.decode("utf-8")
        print("Recovered flag as string:", flag_str)
    except UnicodeDecodeError:
        print("Recovered flag (non-text binary):", flag)

main()
