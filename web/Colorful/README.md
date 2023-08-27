# Colorful

### Flag : `ENO{W3B_H4S_Crypto}`

We first analyse the `flask` code give to us. Essentially we need to set the `is_admin` flag to `1` which will give us the flag.

First, we exploit the `AES` code by generating a payload with overwrites the 2nd ECB block and changes `in=0` to `in=1`. 

We pass this payload and generate a cookie from the response of our post request.

Then we edit the initial part of the cookie and overwrite it with our own, which we then pass in another request.

It gives us the flag.

