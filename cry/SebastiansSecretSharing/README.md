# Sebastian's Secret Sharing

## Challenge Description

I met Adi on a conference and decided to implement my own Secret Sharing Service.

It's pretty rudimentary, but gets the job done. Let's just hope, I didn't do anything wrong...

## Challenge Writeup

We are given a file `sss.py`. We open it up and give it a read:

```py
#!/usr/bin/env python3
import random
from decimal import Decimal,getcontext

class SeSeSe:
	def __init__(self, s, n, t):
		self.s = int.from_bytes(s.encode(), "big")
		self.l = len(s) 	
		self.n = n
		self.t = t
		self.a = self._a()

	def _a(self):
		c = [self.s]
		for i in range(self.t-1):
			a = Decimal(random.randint(self.s+1, self.s*2))
			c.append(a)
		return c

	def encode(self):
		s = []
		for j in range(self.n):
			x = j
			px = sum([self.a[i] * x**i for i in range(self.t)]) 
			s.append((x,px))
		return s

	def decode(self, shares):
		assert len(shares)==self.t
		secret = Decimal(0)
		for j in range(self.t):
			yj = Decimal(shares[j][1])
			r = Decimal(1)
			for m in range(self.t):
				if m == j:
					continue
				xm = Decimal(shares[m][0])
				xj = Decimal(shares[j][0])

				r *= Decimal(xm/Decimal(xm-xj))
			secret += Decimal(yj * r)
		return int(round(Decimal(secret),0)).to_bytes(self.l).decode()


if __name__ == "__main__":
	getcontext().prec = 256 # beat devision with precision :D 
	n = random.randint(50,150)
	t = random.randint(5,10)
	sss = SeSeSe(s=open("flag.txt",'r').read(), n=n, t=t)
	
	shares = sss.encode()

	print(f"Welcome to Sebastian's Secret Sharing!")
	print(f"I have split my secret into 1..N={sss.n} shares, and you need t={sss.t} shares to recover it.")
	print(f"However, I will only give you {sss.t-1} shares :P")
	for i in range(1,sss.t):
		try:
			sid = int(input(f"{i}.: Choose a share: "))
			if 1 <= sid <= sss.n:
				print(shares[sid % sss.n])
		except:
			pass
	print("Good luck!")
```

The whole idea is similar to [Shamir's Secret Sharing Scheme](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing). It is a threshold secret sharing scheme and the intenion of this script would have been to implement a $(t,n)$ sharing scheme. The share indices are integers in the range $[0, n-1]$. Let us assume that the integer encoding of the message is $m$. Then the shares are given as:
$$\text{shares}[i] = (i, m + \sum_{j=1}^t a_ji^j)$$

Now, the challenge allows us to take any $t-1$ shares from the $n$ shares. Ideally, that should make it impossible for us to get the message in a $(t,n) sharing scheme. However, we will recover it by requesting just one share. The bug is in the following piece of implementation:

```py
sid = int(input(f"{i}.: Choose a share: "))
if 1 <= sid <= sss.n:
  print(shares[sid % sss.n])
```

Note that $\text{shares}[0] = m$ is the message, and this should not be distributed to anyone. And they have kept $0$ out of the acceptable `sid` range. However, they perform a `sid % sss.n% for calculating the index and they allow the `sid` to be `sss.n`. So if we simply set our input `sid` to be $n$, it will give us $\text{shares}[n % n] = \text{shares}[0] = m$.<br>
We connect to the server, look at the value of $n$ that's printed and simply send that as our chosen share index to retrieve the integer representation of the flag, which we can then covert to the string representation to recover the flag:<br>
**ENO{SeCr3t_Sh4m1r_H4sh1ng}**
