#!/usr/bin/env python3
import sys

from signatures import schnorr_sign, ecdsa_sign, schnorr_verify, ecdsa_verify, generate_keys
#from flag import FLAG

def main():
	seckey, pubkey = generate_keys()
	print("Welcome in our mixed signature system.\n")
	print(f"My public key is {pubkey.to_bytes().hex()}")

	while True:
		print("\nWhat do you want to do:")
		print("1: Get a Schnorr signature")
		print("2: Get a ECDSA signature")
		print("3: Get the flag")
		print("4: Quit")

		choice = int(input())

		if choice == 1:
			print("Give me a message to sign:")
			msg = input().encode()
			if msg == b"Flag please":
				print("Nope")
				continue
			print(f"{schnorr_sign(msg, seckey).hex()}\n")
		elif choice == 2:
			print("Give me a message to sign:")
			msg = input().encode()
			if msg == b"Flag please":
				print("Nope")
				continue
			print(f"{ecdsa_sign(msg, seckey).hex()}\n")
		elif choice == 3:
			print("Give me a signature of the message \"Flag please\":")
			msg = b"Flag please"
			signature = input()
			signature = bytes.fromhex(signature)
			if ecdsa_verify(msg, pubkey, signature) or schnorr_verify(msg, pubkey, signature):
				print(f"Well done here is the flag: {FLAG}")
			else:
				print("Nope")
		else:
			print("Bye")
			break
	sys.exit()

if __name__ == "__main__":
    main()
