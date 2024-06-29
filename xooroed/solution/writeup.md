# Writeup
## Step 1
We were given a simple txt file with some encrypted message in that. To analyse the file let's run cat on it.
```
cat -A message.txt
```
<image src='./images/enc_message.png'/>


## Step 2
The message is in hex bytes with xor cryptography as hinted in description. To decrypt that we will be using key "xoored" in below website.
```
https://www.dcode.fr/xor-cipher
```
Use Key as "ASCII" with value "xoored"
<image src='./images/decrypting_message.png'/>

## Step 3
Now, the flag can be obtained through the portal output.

The flag is `CZ4067{sup3r_crypt0_h1ts_b4ck}`

<image src='./images/flag.png'/>
