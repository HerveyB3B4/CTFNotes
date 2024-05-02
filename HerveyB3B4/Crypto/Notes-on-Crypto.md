# 密码学做题笔记

## 1 工具使用

### 1.1  [Ciphey](https://github.com/Ciphey/Ciphey)

使用 `python3 -m pip install ciphey --upgrade` 安装 Ciphey

使用方法:

```shell
ciphey -f encrypted.txt
ciphey -- "Encrypted input"
ciphey -t "Encrypted input"
```

## 2 练习记录

### [Crypto-一眼就解密](https://buuoj.cn/challenges#%E4%B8%80%E7%9C%BC%E5%B0%B1%E8%A7%A3%E5%AF%86)

易知这是一段 base64 编码，直接使用 Ciphey 解密即可

```shell
┌──(hervey㉿Hervey)-[~]
└─$ ciphey -t "ZmxhZ3tUSEVfRkxBR19PRl9USElTX1NUUklOR30="
Possible plaintext: 'flag{THE_FLAG_OF_THIS_STRING}' (y/N): y
╭───────────────────────────────────────────────────╮
│ The plaintext is a Capture The Flag (CTF) Flag    │
│ Formats used:                                     │
│    base64                                         │
│    utf8Plaintext: "flag{THE_FLAG_OF_THIS_STRING}" │
╰───────────────────────────────────────────────────
```

### [Crypto-MD5](https://buuoj.cn/challenges#MD5)

打开文件得到一段密文，根据提示猜测这是一段 MD5 校验码

使用 [cmd5](https://www.cmd5.org/) 进行解密

得到 flag 为

```plain
flag{admin1}
```

### [Crypto-Url编码](https://buuoj.cn/challenges#Url%E7%BC%96%E7%A0%81)

根据题目可以知道这是Url编码，用 Ciphey 解密即可

```shell
┌──(hervey㉿Hervey)-[~]
└─$ ciphey -- "%66%6c%61%67%7b%61%6e%64%20%31%3d%31%7d"
Possible plaintext: 'flag{and 1=1}' (y/N): y
╭────────────────────────────────────────────────╮
│ The plaintext is a Capture The Flag (CTF) Flag │
│ Formats used:                                  │
│    urlPlaintext: "flag{and 1=1}"               │
╰────────────────────────────────────────────────╯
```

### [Crypto-看我回旋踢](https://buuoj.cn/challenges#%E7%9C%8B%E6%88%91%E5%9B%9E%E6%97%8B%E8%B8%A2)

可以返现这是一段位移为 13 的凯撒加密，用 Ciphey 解密即可

```shell
┌──(hervey㉿ZHW)-[~]
└─$ ciphey -- "synt{5pq1004q-86n5-46q8-o720-oro5on0417r1}"
Possible plaintext: 'flag{5cd1004d-86a5-46d8-b720-beb5ba0417e1}' (y/N): y
╭────────────────────────────────────────────────────────────────────╮
│ The plaintext is a Capture The Flag (CTF) Flag                     │
│ Formats used:                                                      │
│    caesar:                                                         │
│     Key: 13Plaintext: "flag{5cd1004d-86a5-46d8-b720-beb5ba0417e1}" │
╰────────────────────────────────────────────────────────────────────╯
```

### [Crypto-摩丝](https://buuoj.cn/challenges#%E6%91%A9%E4%B8%9D)

打开文件后得到

```plain
.. .-.. --- ...- . -.-- --- ..-
```

是一段摩斯密码，解密后得到

```plain
ILOVEYOU
```

得到 flag 为

```plain
flag{ILOVEYOU}
```

### [Crypto-password](https://buuoj.cn/challenges#password)

打开文件后得到

```plain
姓名：张三 
生日：19900315

key格式为key{xxxxxxxxxx}
```

密码有十位，猜测是 "姓名首字母+生日" 组合

```plain
key{zs19900315}
```

得到 flag 为

```plain
flag{zs19900315}
```

### [Crypto-变异凯撒](https://buuoj.cn/challenges#%E5%8F%98%E5%BC%82%E5%87%AF%E6%92%92)

打开文件后得到

```plain
加密密文：afZ_r9VYfScOeO_UL^RWUc
格式：flag{ }
```

根据题目提示可以得知应该是凯撒加密变种，将已知字符一一对应

|$\Delta$|5|6|7|8|9|?|?|?|?|?|?|?|?|?|?|?|?|?|?|?|?|26|
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
|密文|a|f|Z|_|r|9|V|Y|f|S|c|O|e|O|_|U|L|^|R|W|U|c|
|明文|f|l|a|g|{| | | | | | | | | | | | | | | | |}|

发现位移每次增加 1 ，由此，我们可以写出解密脚本

```plain
secret_text = "afZ_r9VYfScOeO_UL^RWUc"
flag = ""
for i in range(len(secret_text)):
    flag += chr(ord(secret_text[i]) + 5 + i)
print(flag)
```

运行得到 flag

```plain
┌──(hervey㉿Hervey)-[/mnt/c/Users/hervey/Downloads]
└─$ python3 ./dec.py
flag{Caesar_variation}
```
