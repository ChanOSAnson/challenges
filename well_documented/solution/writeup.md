# Writeup
## Step 1
We were given a PDF file with some redacted text on it.
<image src='./images/pdf.png'/>


## Step 2
To read the text hidden behind PDF file , use a tool called pdf2txt to uncover hidden text
```
pdf2txt ../dist/secret.pdf | grep CZ4067
```
We get the  hidden message.
<image src='./images/flag_forensics.png'/>

The flag is `CZ4067{00ps_s1lly_m1st4k3}`
