# Heavens Flow

We first de-compile the binary using binaryninja. 
We see a function `heavens_secret` which prints the flag.
The binary is not a PIE, so we can get the address of that function.
In the main function, to read the chosen option, program uses `gets`.
So, we send option, followed by padding and return to the function `heavens_secret`

We get the flag:
**ENO{h34v3nly_4ddr355_f0r_th3_w1n}**

---

<sup>Author: anibal\_hacker</sup>
