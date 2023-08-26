from pwn import *
from sage.all import *
from Crypto.Util.number import long_to_bytes

HOST = "52.59.124.14"
PORT = int(10008)
target = remote(HOST, PORT)

def recvline():
    return target.recvuntil(b"\n").decode()

recvline() # My public modulus is:
n = int(recvline())
recvline() # Let me count how long it takes you to find the secret token.
c1 = int(recvline())
recvline() # What is your guess?
target.sendline(b"1")
c2 = int(recvline())
recvline() # What is your guess?

#===
def gcd(a, b):
    while b:
        a, b = b, a%b
    return a.monic()



def franklinreiter(C1, C2, e, N, a, b):
    P.<X> = PolynomialRing(Zmod(N))
    g1 = (a*X + b)^e - C2
    g0 = X^e - C1

    g = gcd(g0, g1)
    if g == 1:
        return -1
    else:
        return int(-g[0])%n

a = 1
b = 1942668892225729070919461906823518906642406839052139521251812409738904285205208498176

for i in range(0, 40):
    print(i)
    if franklinreiter(c1, c2, 1337, n, a, b) != -1:
        token = long_to_bytes(franklinreiter(c1, c2, 1337, n, a, b))[-i:]
        break
    b *= 256

print(token)

# token is a bytes object
target.sendline(token)
target.interactive()
