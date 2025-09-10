Generate a template for this exploit with `pwnkit`:
```
pip install pwnkit
pwnkit xpl.py -f ./pstack -l ./libc.so.6 -t ret2libc
```

# Writeup

/

# Memos

* Stack pivot
* Control RBP
* Leak libc puts
* ROP
* ret2libc
* Glibc 2.35

