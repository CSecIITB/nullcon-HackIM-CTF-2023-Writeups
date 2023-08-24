# Curvy Decryptor

### Flag : `ENO{ElGam4l_1s_mult1pl1cativ3}`

We first analyze the code given in `curvy_decryptor.py`.

We are given an Elliptic curve $y^2 = x^3 + ax + b \pmod p$ with a large order $n$. We are also given a point $G$ on the curve. 
The order is a prime number, and hence points on the curve cannot be distributed into smaller subgroups. The elliptic curve by itself (P-256 with a = -3) can be found commonly in literature and is unlikely to be exploitable by itself.

```python
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
curve = EllipticCurve(p,a,b, order = n)
G = ECPoint(curve, 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
```

The public key is a point $P_a$, which is $G$ multiplied by a random 32-byte scalar $d_a$.

```python
d_a = bytes_to_long(os.urandom(32))
P_a = G * d_a
```

The encrypt function first generates a point $m$ on the curve by setting the x-coordinate of $m$ as the encoded message. Then it returns a pair of points $B = G*d_b$ and $c = m + \text{pubkey}*d_b$.

```python
def encrypt(msg : bytes, pubkey : ECPoint):
	x = bytes_to_long(msg)
	y = modular_sqrt(x**3 + a*x + b, p)
	m = ECPoint(curve, x, y)
	d_b = number.getRandomRange(0,n)
	return (G * d_b, m + (pubkey * d_b))
```

The decrypt function is inverse of the encrypt function which returns decoded message by calculating $c - B*d_a$ and taking its x-coordinate.

```python
def decrypt(B : ECPoint, c : ECPoint, d_a : int):
	if B.inf or c.inf: return b''
	return long_to_bytes((c - (B * d_a)).x)
```

Essentially,
$$\text{Decrypt}(\text{Encrypt}(\text{message}, p), ~ p) = \text{message}$$

When the programme starts, it displays the values of $P_a \text{pubkey}, B_0$ and $c_0$ which were obtained by encrypting the flag.

```
print('My public key is:')
print(P_a)
print('Good luck decrypting this cipher.')
B,c = encrypt(flag1, P_a)
print(B)
print(c)
```

After printing the encryption for `flag2`, it asks us to input values for decryption. 

```python
print('B:', end = '')
sys.stdout.flush()
B_input = sys.stdin.buffer.readline().strip().decode()
print('c:', end = '')
sys.stdout.flush()
c_input = sys.stdin.buffer.readline().strip().decode()
```

The code then uses the coordinates inputted to generate 2 points $B$ and $c$ on the Elliptic curve.

Using these $B$ and $c$ with the public key $P_a$, it uses the $\text{Decrypt}$ function to generate a message `msg`.

```python
B = ECPoint(curve, *[int(_) for _ in B_input.split(',')])
c = ECPoint(curve, *[int(_) for _ in c_input.split(',')])
msg = decrypt(B, c, d_a)
```

If the message has `ENO` as a substring, then `balance` immediately becomes $-1$ and the code terminates. Otherwise, it prints the message.

With this in mind, we look for an exploit.

## The Exploit

We know that $\text{Encrypt(flag1, }P_a) = (B_0, c_0)$, and on passing these points into the $\text{Decrypt}$ function, we will get back the flag.

$$\text{flag1} = \text{Decrypt}(B_0, c_0, P_a)$$

However, on passing $B_0, c_0$ as $B$ and $c$, the variable `msg` will start with `ENO` and immediately reduce the balance.

```python
if b'ENO' in msg:
	balance = -1
```

Due to this, the programme will not output anything.

We need to think of some different input to the $\text{Decrypt}$ function so that it returns something from which extracted flag can be extracted, but is different from the flag itself.

The main part of the decrypt function is computing the point $T$ where
$$T = c - B*d_a$$

With $c = c_0 = m + P_a*d_b = m + G*d_a*d_b$ and $B = B_0 = G*d_b$,

$$\begin{align*}T &= c_0 - B_0*d_a \\ &= m + G*d_a*d_b - (G*d_a)*d_b \\ &= m\end{align*}$$

And the `flag1` is encoded in the x-coordinate of point $m$.

Due to additivity of points on Elliptic curves, we can pass a point $c' = c_0 + X$ and $B = B_0$ where $X$ is a point on the same elliptic curve, and get the value of $T' = c' - B*d_a$

$$\begin{align*}T' &= c' - B*d_a \\ &= c_0 + X - B_0*d_a \\ &= m + X + G*d_a*d_b - (G*d_a)*d_b \\ &= m + X\end{align*}$$

Later we can subtract $X$ from $T'$ to get $m = T' - X$.

Hence, if we find and use any point on the curve as $X$, we are done.

There is a very small probability that even the `msg` decoded from x-coordinate of $T'$ will contain the string `ENO` and balance will still remain positive.

We can find a point $X$ on the curve by randomly selecting its x-coordinate, but we already know a point $G$ which lies on the curve and can be used as $X$.

Hence, we should pass $B = B_0$ and $c = c_0 + G$ as our input.

All the functions (modular $+$ and $-$) required in our calculations are already implemented in the `utils.py` file provided.

To interact with the server, we use `pwntools` library in `python`.

Here is the code.

```python
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
```

Running, 

```bash
$ python3 solve.py 
$ [+] Opening connection to 52.59.124.14 on port 10005: Done
$ ENO{ElGam4l_1s_mult1pl1cativ3}
$ [*] Closed connection to 52.59.124.14 port 10005
```