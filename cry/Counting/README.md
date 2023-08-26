# Counting

### Flag : `ENO{th3_s0lut1on_i5_n0t_th4t_1337}`

On analyzing the code, we see that the programme first generates a random number `token`, which has the same bytes as length of the flag.

```python
key = RSA.generate(2048, e = 1337)
token = os.urandom(len(flag))
```

Then using standard RSA with `e=1337`, it encrypts a message in every iteration of the loop and prints the encrypted message.

```python
message = b'So far we had %03d failed attempts to find the token %s' % (counter, token)
```

Since counter ranges from $0$ to $127$, using `%03d` substitutes a 0-padded three digit counter in the message text in every iteration.

Finally the programme takes an input from us, and if we correctly guess the token, it gives us the flag.

```python
guess = sys.stdin.buffer.readline().strip()
    if guess == token:
        print('Congratulations for finding the token after %03d rounds. Here is your flag: %s' % (counter, flag))
```

Seeing the structure of the cleartext `message` variable, we write an exploit.

## The Exploit

Observe that for a particular instance of this programme, the first 2 values of `message` just differ by having counter as $0$ and $1$.

Essentially, we have,

```python
message0 = b'So far we had 000 failed attempts to find the token %s' % token
```
and
```python
message1 = b'So far we had 001 failed attempts to find the token %s' % token
```

Only 1 character changes from `message0` to `message1` which is the counter.

Hence, if we can get the length of `token`, we can determine the exact difference between the `bytes_to_long` encoding of these messages.

If $M_0$ and $M_1$ denote `bytes_to_long(message0)` and `bytes_to_long(message1)` respectively,

$$M_1 - M_0 = ('1' ~ - ~'0') \cdot 2^n$$

where $n$ is determined by the length of token.

Let us first find how exactly $n$ is related to the length of token (equal to length of `flag`).

We can do that by comparing 2 messages with token as an empty string `""`.

```python
>>> from Crypto.Util.number import bytes_to_long
>>> message0 = b'So far we had %03d failed attempts to find the token %s' % (0, b"")
>>> message1 = b'So far we had %03d failed attempts to find the token %s' % (1, b"")
>>> x = bytes_to_long(message1) - bytes_to_long(message0)
>>> x
1942668892225729070919461906823518906642406839052139521251812409738904285205208498176
>>> log(x, 2)
280.0
```
Hence,

$$M_1 - M_0 = 1 \cdot 2^{(\text{len(flag)}*8 + 280)}$$

$$M_1 - M_0 = 2^{280} \cdot 256^{\text{len(flag)}}$$

Since `len(flag)` is expected to be a small number, it can be brute-forced later.

Now we have the 2 equations,

$$C_0 \equiv M_0^{~ 1337} \mod N$$
$$C_1 \equiv M_1^{~ 1337} \mod N$$

where $M_1 = M_0 + b$, and $b$ is a known constant.

We can now apply the [Franklin-Reiter Related Message Attack](https://stackoverflow.com/questions/73757974/how-to-perform-a-franklin-reiter-related-message-attack-on-rsa) on this RSA system.

The second equation can be written as

$$C_1 \equiv (M_0+b)^{~ 1337} \mod N$$

Hence, if we consider the polynomial ring modulo $N$, the integer $M_0$ is a root of both 
$$g_0(x) = x^{1337} - C_0$$
$$g_1(x) = (x+b)^{1337} - C_1$$

Hence, $(x - M_0) ~|~ g_0$ and $(x - M_1) ~|~ g_1$ which implies $$(x - M_0) ~|~ gcd(g_0, g_1)$$

If we can factor the polynomial $gcd(g_0, g_1)$, then $(x - M_0)$ will be one of the linear factors.

From this, we can obtain $M_0$ and then get the token.

We can execute this exploit using `sage` and `pwntools` and brute force over `n = len(flag)` to get the flag.

Here is the code.

```python
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
```

On running we get,

```
Congratulations for finding the token after 001 rounds. Here is your flag: ENO{th3_s0lut1on_i5_n0t_th4t_1337}
```













