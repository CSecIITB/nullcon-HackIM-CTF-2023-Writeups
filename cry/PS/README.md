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
	print(encrypt(smflag, key))

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

### Coppersmith's Theorem and Friends

> **Coppersmith's Theorem:** Let $N$ be an integer and $f \in \mathbb{Z}[x]$ be a monic polynomial of degree $d$ over the integers. Set $X =  N^{1/d - \epsilon}$ for $\frac{1}{d} > \epsilon > 0$. Then, given $\langle N,f\rangle$, attacker can efficiently find all integers $x_0 < X$ satisfying $f(x_0) \equiv 0 \pmod{N}$. The running time is dominated by the time it takes to run the LLL algorithm on a lattice of dimension $\mathcal{O}(w)$ with $w = \min[\frac{1}{\epsilon}, \log_2N]$.

The theorem essentially states that we have an "efficient" algorithm to find small roots of $f$ modulo (possibly) a composite $N$. The implementation of this algorithm uses a clever reduction to lattices and is beyond the scope of this writeup (I might write up about it elsewhere sometime though, but not here, not for now). 

Another thing we'd need before we can look at Coppersmith's Short Pad Attack is the Franklin-Reiter Related Message Attack:

> **Franklin-Reiter:** Let $\langle N, e \rangle$ be an RSA public key. Let $M_1 \neq M_2 \in \mathbb{Z}_N^*$ satisfy $M_1 \equiv f(M_2) \pmod{N}$ for some linear polynomial $f = ax + b \in \mathbb{Z}_N[x]$ with $b \neq 0$. Then given $\langle N, e, C_1, C_2, f \rangle$, attacker can recover $M_1, M_2$ in time quadratic in $e \cdot \log N$.

Note that $e$ being small helps significant in the practical runtime. How this attack works is something that can be covered in this writeup though, so let's go with that! <br>
It can be easily observed that $M_2$ is a common root of the polynomials $g_1(x) = f(x)^e - C_1 \in \mathbb{Z}_N[x]$ and $g_2(x) = x^e - C_2 \in \mathbb{Z}_N[x]$. Thus, $(x - M_2)$ is a common factor of both $g_1, g_2$. Now, we can use the Euclidean algorithm to calculate $gcd(g_1, g_2)$ and if it is linear, we can recover $M_2$.<br>
[Technical Aside: Note that $\mathbb{Z}_N[x]$ is not an Euclidean Domain. However, we could still try and hope that the Euclidean Algorithm works. If it does not, looking at where the algorithm "breaks" would give us information on the factorisation of $N$.]

> **Coppersmith's Short Pad Attack:** Let $\langle N, r \rangle$ be a public RSA key, where $N$ is $n$ bits long. Set $m = \lfloor \frac{n}{e^2} \rfloor$. Let $M \in \mathbb{Z}_N^*$ be a message of length at most $n - m$ bits. Define $M_1 = 2^mM + r_1$ and $M_2 = 2^mM + r_2$, where $r_1$ and $r_2$ are distinct integers with $0 \le r_1, r_2 < 2^m$. If attacker is given $\langle N, e \rangle$ and the encryptions $C_1, c_2$ of $M_1, M_2$ (but is not given $r_1, r_2$), she can efficiently recover $M$.

Again, having $e$ small is what allows this attack to work by allowing a sufficiently large enough padding length.<br>
Consider the polynomials $g_1(x) = x^e - C_1 \in \mathbb{Z}_N[x]$ and $g_2(x,y) = (x+y)^e - C_2 \in \mathbb{Z}_N[x]$. We can see that when $y = r_2 - r_1$, these polynomials have $M_2$ as a common root. The resultant of two polynomials is a multivariate polynomial on the coefficients of the two given polynomials which evaluates to zero when the two given polynomials have a common root. Thus, $\Delta = r_2 - r_1$ would be a root of the resultant $h(y) = res_x(g_1, g_2) \in \mathbb{Z}_N[y]$. Since $\Delta < 2^m < N^{1/e^2}$, $\Delta$ must be a small root of $h$ modulo $N$ which can be recovered using Coppersmith's method. With the knowledge of $\Delta$, $M_2$ can be recovered using the Franklin-Reiter attack. Stripping the padding off of $M_2$, we recover $M$.

### Attack Methodology for the Challenge

Given that $n = 2048$ and $e = 3$, the maximum amount of padding for which Coppersmith's Short Pad attack would work is $m = \lfloor \frac{n}{e^2} \rfloor = \lfloor \frac{2048}{9} \rfloor = 227$, which is more than sufficient because we only have 128 bits of padding. We take the ciphertexts we had received earlier and plug them into `C1` and `C2` in the following script and run to retrieve the flag:

```py
from Crypto.Util.number import long_to_bytes

C1 = 919052997942427307726583335637159074460863592763419213239331601517138499346034489264805275246795047403378055738568713378177590755883226021551548871645003631552026681627296633273433797487415716926723029871442662900749190470163667208454128508790282471679591695692053573482413544308508462036639735286639212087590592847936585543335950629909021736410714681667083165916884036779009406845246284057242619731653612075480782691343683777055465013274434160784537532244068414760340433467741472814246493488575884022713448634683073688063747738523053811306156333568351053594637905935615148751767918930618350137922900548902927697909
C2 = 14743668642440243543492861117016936663893228627335542739791839186975127534122994903465929852909201858028177975052037346463577142447425255657006049889597834425593873332888179764909368022041648150310497469594267062347791382917523654105300840617809311482917671490044874249854541153029953731060325080194882352991230908200543319719548031971654084745587253903494440360040708406458043146859386635281890364297268716286842255094806976955660578251715848490044584347587808944311681537115568328574580752669084215810246859345376623610139105217494841550615603106907559492675963257888490673532140829020897240260833251495982775692830
N = 30365438743698062397406930590949269280593048377850893613413558166236105244083066056495446502323868239203526962089713620387515798023123230010124377575540557582429186708428668867093995765077728669594890084306388503647802964757302289760685819602551597527355487132115877795021324835185505651991755830083321281510280709767186980834085346023734786595739310306267562611674462733516685699311769265913880592132764370784305505650526655107465772214479832986381272985584375802890178838921661673848530894049243701012349431866390642722353500240314560001617057489476106062378326273333365822122131795069188464898611484493332124596553

e = 3

# ===== Coppersmith's Short Pad Attack =====
PRxy.<x,y> = PolynomialRing(Zmod(N))
PRx.<xN> = PolynomialRing(Zmod(N))
PRZZ.<xz,yz> = PolynomialRing(Zmod(N))
 
g1 = (x**e - C1).change_ring(PRZZ)
g2 = ((x + y)**e - C2).change_ring(PRZZ)
 
h = g2.resultant(g1)
h = h.univariate_polynomial()
h = h.change_ring(PRx).subs(y=xN)
h = h.monic()
 
# ===== Coppersmith's Method =====
roots = h.small_roots(X=2**128, beta=0.3)
# ===== Coppersmith's Method =====

delta = roots[0]
if delta > 2**32:
    delta = -delta
    C1, C2 = C2, C1

# ===== Franklin-Reiter =====
x = PRx.gen()
g1 = x**e - C1
g2 = (x + delta)**e - C2
 
while g2:
    g1, g2 = g2, g1 % g2
 
g = g1.monic() 
pt = -g[0]
# ===== Franklin-Reiter =====
# ===== Coppersmith's Short Pad Attack =====

print(long_to_bytes(int(pt)))
```

The script outputs the flag:<br>
**ENO{we11_5eem5_lik3_128_r4ndom_b1ts_4r3_n0t_3n0ugh}**

---

<sup>**Author:** Nilabha</sup>
