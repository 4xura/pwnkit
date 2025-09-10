Generate a template for this exploit with `pwnkit`:
```
pip install pwnkit
pwnkit xpl.py -f ./pstack -l ./libc.so.6 -t ret2libc
```

# Writeup

/

# Notes

* Stack pivot
* Control RBP
* Leak libc puts
* ROP
* Glibc 2.35

