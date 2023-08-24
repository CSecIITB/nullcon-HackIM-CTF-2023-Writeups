from pwn import *
from sage.all import *
from Crypto.Util.number import long_to_bytes

HOST = "52.59.124.14"
PORT = int(10008)
target = remote(HOST, PORT)

def recvline():
    return target.recvuntil(b"\n").decode()

recvline()
n = int(recvline())
recvline()
c1 = int(recvline())
recvline()
target.sendline(b"1")
c2 = int(recvline())
recvline()

#===
def gcd(a, b):
    while b:
        a, b = b, a%b
    return a.monic()



def franklinreiter(C1, C2, e, N, a, b):
    P.<X> = PolynomialRing(Zmod(N))
    g1 = (a*X + b)^e - C2
    g2 = X^e - C1
    result = -gcd(g1, g2)[0] + N
    return result

a = 1
b = 14742040721959145907193572581985425355144223517251720423344555860334469384344331453461432520225229560708860839963921269139728846210643721220943102544658968920505450496


token = long_to_bytes(int(franklinreiter(c1, c2, 1337, n, a, b)))[-34:]
print(token)

# token is a bytes object
# token = pass
target.sendline(token)
target.interactive()
