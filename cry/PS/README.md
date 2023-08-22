# PS

## Challenge Description
I prepared a message for Alice but if you'd like to add a PS of your own, feel free to do so.

## Challenge Writeup
We begin by looking at the source code:

```py
#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, long_to_bytes
import sys
from secret import flag

key = RSA.generate(2048, e = 3)

def encrypt(msg : bytes, key) -> int:
	m = bytes_to_long(msg)
	if m.bit_length() + 128 > key.n.bit_length():
		return 'Need at least 128 Bit randomness in padding'
	shift = key.n.bit_length() - m.bit_length() - 1
	return pow(m << shift | number.getRandomInteger(shift), key.e, key.n)

def loop():
	print('My public modulus is:\n%d' % key.n)
	print('Here is your secret message:')
	print(encrypt(flag, key))

	while True:
		print('You can also append a word on your own:')
		sys.stdout.flush()
		PS = sys.stdin.buffer.readline().strip()
		print('With these personal words the cipher is:')
		print(encrypt(flag + PS, key))

if __name__ == '__main__':
	try:
		loop()
	except Exception as err:
		print(repr(err))
```

We note that the challenge uses a 2048-bit key RSA encryption with a low public exponent ($e = 3$). It takes in some "personal words" from us, appends that to the flag, then pads the result with random bits before encrypting it. An important requirement is that it requires at least 128 bits of padding otherwise it rejects the encryption. <br>
The idea is to use Coppersmith's Short Pad Attack (more on this in a bit) to retrieve the flag. For this, we need to get encryptions of two messages, both with exactly 128 bits of random padding (actually, we do not need _exactly_ 128 bits of padding, but we shall assume that here for simplicity). We do not know the length of the flag, so we can instead do a (manual) binary search on the length of our "personal words" so that we have exactly 128 bits of padding on the message. We find out that a length of "personal words" of 189 achieves the same.<br>
We request the encryption twice with the same "personal words" of length 189 (say, `'A'*189`) and obtain the corresponding ciphertexts. Now we can use Coppersmith's Short Pad attack to retrieve the flag.

[To Be Completed]
