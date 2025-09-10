Generate a template for this exploit with `pwnkit`:

```bash
pip install pwnkit
pwnkit xpl.py -t heap
```

## Writeup

About libc got hijacking: https://4xura.com/binex/pwn-got-hijack-libcs-internal-got-plt-as-rce-primitives/

## Memos

* Off by Null
* House of Einherjar
* Heap fengshui
* Chunk overlapping
* Tcache poisoning
* Hijack `tcache_perthread_struct`
* Libc got Hijack 
* Glibc 2.35
