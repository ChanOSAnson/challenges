# Writeup
## Step 1
We were given a simple txt file with some message in that. To analyse the file let's run cat on it.
```
cat -A message.txt
```
<image src='./images/message_chars.png'/>


## Step 2
The message had extra bytes hidden inside which didn't made any sense, so we can try unicode steganography to uncover what's behind those hidden bytes.
```
https://330k.github.io/misc_tools/unicode_steganography.html
```
We get the encoded hidden message.
<image src='./images/encoded_message.png'/>

## Step 3
Now, the flag can be obtained by decoding the hex message.
```
echo 435a343036377b5734726e33645f34623075745f6675747572335f316e76347331306e7d0a | xxd -r -p
```

The flag is `CZ4067{W4rn3d_4b0ut_futur3_1nv4s10n}`
