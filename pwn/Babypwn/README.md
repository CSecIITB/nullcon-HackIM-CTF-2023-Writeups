# Babypwn

The source code shows that username has 512 bytes on stack but it is reading 1024 bytes.
So, we can overwrite the return address.
The program also prints the address where the input username is stored.

We run the program and check the memory mappings.
We see that the stack is executable. 
```
  0x7fff81fae000     0x7fff81fcf000    0x21000        0x0  rwxp   [stack]
```

We then use shellcode to spawn shell and add padding to overwrite return address
to the position of shellcode on stack.

For running the exploit locally, using `p.sendline` function of pwntools 
didn't work because the `read` used $fd=1$ to read.
So, to run exploit locally, use `p.proc.stdout.write`.

We get the flag:

**ENO{Even_B4B1es_C4n_H4ck!}**


---

<sup>Author: anibal\_hacker</sup>
