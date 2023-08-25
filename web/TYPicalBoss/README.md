>**Problem Statement:** My boss just implemented his first PHP website. He mentioned that he managed to calculate a hash that is equal to 0??? I suppose he is not very experienced in PHP yet. Author: @moaath

- Given the problem statement we can figure 2 very important things:  
	1. The website is made using **PHP language**.  
	2. The **password hash of some user** is turning out to be **0 when password check is done**.
- **_“Password hash evaluates to 0”_** is a special case in PHP script when 2 conditions are met,  
	1. Type Juggling in PHP: Evaluation is done using "\=\=" and not “\=\=\=”  
	2. The password hash is in form “0e\[0–9]…”, ideally first 2 characters are “0e” and 3rd character is a digit.
- Since we don’t know the source code, lets assume the source code may be of kind:
```php
HASH("<some-password>") == "<hash-of-admin-password>"
```
- If above is the case then because “\=\=” is used, Type Juggling is possible, where PHP performs “weak comparison” and in specific cases where there is a “\<int> == \<string>” comparison and type cast to integer is possible, it converts the string to integer and compares integer with integer.
- In our case for “\<hash-of-admin-password>” to turn out to be “0” when “Type Juggling” is done, “0e” must be the first 2 characters of of the hash and the 3rd character must be a digit (\[0–9]). If the condition is met, then PHP will convert the \<hash-of-admin-password> as integer 0 because “0e\[0–9]….” is a form of exponential notation and thus PHP ignore all characters from 4th position to last and evaluates it to 0^(something) which is 0.
- Keeping the theoretical guess in mind, what we need is a valid username and a password whose hash (potentially anything SHA1,MD5,SHA256,etc) turns out to be in the form of “0e\[0–9]…”.
- For this particular challenge, the valid username is “admin” and the password to use is “10932435112” with SHA1 hashing scheme.
- For more detailed understanding checkout this [stackexchange](https://security.stackexchange.com/questions/268218/crashing-the-sha1-function-in-php) post.

FLAG: _ENO{m4ny_th1ng5_c4n_g0_wr0ng_1f_y0u_d0nt_ch3ck_typ35}_
