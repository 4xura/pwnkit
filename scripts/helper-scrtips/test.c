// test.c
#include <stdio.h>

void foo(void) {
    // simple gadget-friendly sequence
    asm("push %rbp; mov %rsp, %rbp; nop; nop; pop %rbp; ret");
}

int main(void) {
    foo();
    puts("hello");
    return 0;
}

