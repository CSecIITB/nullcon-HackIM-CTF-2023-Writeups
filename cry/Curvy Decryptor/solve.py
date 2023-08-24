from pwn import *
from Crypto.Util.number import long_to_bytes
from ec import *
from utils import *

HOST = "52.59.124.14"
PORT = int(10005)
target = remote(HOST, PORT)

def recvline(end):
    return target.recvuntil(end).decode().strip()

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
curve = EllipticCurve(p,a,b, order = n)
G = ECPoint(curve, 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

recvline(b"\n") # My public key is:
pa = [int(x.strip()) for x in recvline(b"\n")[6:-1].split(", ")]
recvline(b"\n") # Good luck decrypting this cipher.
B = [int(x.strip()) for x in recvline(b"\n")[6:-1].split(", ")]
c = [int(x.strip()) for x in recvline(b"\n")[6:-1].split(", ")]
recvline(b"\n") # encrypted flag2
recvline(b"\n") # I will decrypt anythin as long as it does not talk about flags.


recvline(b":") # B:
B_send = str(B[0]) + ", " + str(B[1])
target.sendline(B_send.encode())

recvline(b":") # c:
C_p = ECPoint(curve, c[0], c[1])
P = C_p + G
c_send = str(P.x) + ", " + str(P.y)
target.sendline(c_send.encode())

x = int(recvline(b"\n")[2:-1], 16)
y = modular_sqrt(x**3 + a*x + b, p)
M = ECPoint(curve, x, y) - G

flag1 = long_to_bytes(M.x)
print(flag1.decode())