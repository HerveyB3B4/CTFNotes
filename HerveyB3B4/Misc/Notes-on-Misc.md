# 杂项做题笔记

## 1 工具使用

### 1.1  [stegsolve](http://www.caesum.com/handbook/Stegsolve.jar)

打开`Stegsolve`图片隐写解析器

```bash
java -jar Stegsolve.jar
```

## 2 练习记录

### [Misc-金三胖](https://buuoj.cn/challenges#%E9%87%91%E4%B8%89%E8%83%96)

在`File >> Open`中打开`gif`文件

使用`Analyse >> Frame`逐帧查看

在第`21,51,79`帧寻找到`flag`片段，将其组合在一起获得`flag{he11ohongke}`

### [Misc-LSB](https://buuoj.cn/challenges#LSB)

在`File >> Open`中打开`png`文件

发现在`Red plane 0`, `Green plane 0`, `Blue plane 0`的模式下图片上方有一段色块异常

使用`Analyse >> Data Extract`选中`Red 0, Green 0, Blue 0, LSB First`并`Save Bin`保存为图片

![[flag.png]](./Notes-on-Misc/flag.png)

打开该图片得到一个二维码, 使用`QR Research`扫描获得: `flag{1sb_i4_s0_Ea4y}`

### [Misc-镜子里面的世界](https://buuoj.cn/challenges#镜子里面的世界)

在`File >> Open`中打开`png`文件

发现在`Red plane 0`, `Green plane 0`, `Blue plane 0`的模式下图片全黑

使用`Analyse >> Data Extract`选中`Red 0, Green 0, Blue 0`，得到如下文本

```hex
4865792049207468 696e6b2077652063  Hey I th ink we c
616e207772697465 20736166656c7920  an write  safely 
696e207468697320 66696c6520776974  in this  file wit
686f757420616e79 6f6e652073656569  hout any one seei
6e672069742e2041 6e797761792c2074  ng it. A nyway, t
6865207365637265 74206b6579206973  he secre t key is
3a2073743367305f 7361757275735f77  : st3g0_ saurus_w
7233636b73000000 0000000000000000  r3cks... ........
```

获得`flag{st3g0_saurus_wr3cks}`

### [Misc-二维码](https://buuoj.cn/challenges#二维码)

下载文件并解压获得`QR_code.png`

看起来是个二维码？用`QR Research`扫描一下看:

![[Misc-二维码.png]](./Notes-on-Misc/Misc-二维码.png)

好吧什么都没有...

再用`stegsolve`试试？

一无所获...

或许这并不全是`png`文件?用`binwalk`命令分析一下

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/二维码]
└─$ binwalk QR_code.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 280 x 280, 1-bit colormap, non-interlaced
471           0x1D7           Zip archive data, encrypted at least v2.0 to extract, compressed size: 29, uncompressed size: 15, name: 4number.txt
650           0x28A           End of Zip archive, footer length: 22
```

发现里面还藏了个zip文件，使用`foremost`分离隐藏文件

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/二维码]
└─$ foremost ./QR_code.png 

Processing: ./QR_code.png
�foundat=4number.txtn
Qjxu�J����[����OPF4L�
*|
```

进入`output`文件夹中

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/二维码/output]
└─$ ls

audit.txt  png  zip
```

在`zip`文件夹里有一个`00000000.zip`文件，但是需要密码，由`4number.txt`的提示我们可以猜测密码由四位数字组成，尝试使用`fcrackzip`暴力破解:

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/二维码/output/zip]
└─$ fcrackzip -b -c1 -l 1-4 -u 00000000.zip                                                           


PASSWORD FOUND!!!!: pw == 7639
```

得到密码为`7639`，解压文件`00000000.zip`

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/二维码/output/zip]
└─$ unzip 00000000.zip 
Archive:  00000000.zip
[00000000.zip] 4number.txt password: 
  inflating: 4number.txt             

┌──(hervey㉿Hervey)-[~/Downloads/Misc/二维码/output/zip]
└─$ ls                                                                                                
00000000.zip  4number.txt

┌──(hervey㉿Hervey)-[~/Downloads/Misc/二维码/output/zip]
└─$ cat ./4number.txt                                                                                 
CTF{vjpw_wnoei}
```

成功获得`flag{vjpw_wnoei}`

### [Misc-大白](https://buuoj.cn/challenges#大白)

打开图片，发现无法正常打开(Kali系统下)，用`binwalk`命令查看图片文件

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/dabai]
└─$ binwalk ./dabai.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 679 x 256, 8-bit/color RGBA, non-interlaced
91            0x5B            Zlib compressed data, compressed
```

发现还有一段数据未使用，可能是PNG文件头中宽高设置不正确

>PNG文件结构([PNG File Format - Raster Image File](https://docs.fileformat.com/image/png/))
>00 - 03 : Header `89 50 4E 47`
>08 - 0B : Length
>0C - 0F : Chunk Type Code
>10 - 13 : Width
>14 - 17 : Height
>1D - 20 : CRC

使用如下`Python`脚本获取图片真实大小

```python
import os
import binascii
import struct

#文件名
filename = "dabai.png"
#图片当前CRC(29-32位)
CRC = 0x6d7c7135

crcbp = open(filename, "rb").read()
for i in range(2000):
    for j in range(2000):
        data = crcbp[12:16] + \
            struct.pack('>i', i) + struct.pack('>i', j) + crcbp[24:29]
        crc32 = binascii.crc32(data) & 0xffffffff
        if (crc32 == CRC):
            print(i, j)
            print('hex:', hex(i), hex(j))
```

```bash
┌──(hervey㉿Hervey)-[~/Tools/Misc]
└─$ python calc_pic_size.py 
679 479
hex: 0x2a7 0x1df
```

打开十六进制编辑器, 将`10 - 17`位设置为正确值:

![[Misc-大白.png]](./Notes-on-Misc/Misc-大白.png)

再次打开图片，即可获得`flag{He1l0_d4_ba1}`

![[dabai.png]](./Notes-on-Misc/dabai.png)

### [Misc-你竟然赶我走](https://buuoj.cn/challenges#你竟然赶我走)

解压后发现一张图片，先用`Stegsolve`试试，尝试了一圈发现在某些模式下右下角有些变化，推测可能在文件尾有问题

使用`010 Editor`打开文件，一直拉到最底下，获得`flag{stego_is_s0_bor1ing}`

![[Misc-你竟然赶我走.png]](./Notes-on-Misc/Misc-你竟然赶我走.png)

### [Misc-zip伪加密](https://buuoj.cn/challenges#zip伪加密)

下载文件，先解压

? 怎么加密了

先`binwalk`看看文件结构，看看有没有藏些什么提示

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/zip伪加密]
└─$ binwalk ./ee2f7f26-5173-4e7a-8ea4-e4945e6f04ff.zip 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, encrypted at least v2.0 to extract, compressed size: 25, uncompressed size: 23, name: flag.txt
153           0x99            End of Zip archive, footer length: 22
```

好吧并没有...

考虑到标题是zip伪加密，查了查[zip的文件结构](https://docs.fileformat.com/compression/zip/)

|Offset|Bytes|Description|
|---|---|---|
|0|4|Local file header signature # 0x04034b50 (read as a little-endian number)|
|4|2|Version needed to extract (minimum)|
|6|2|General purpose bit flag|
|8|2|Compression method|
|10|2|File last modification time|
|12|2|File last modification date|
|14|4|CRC-32|
|18|4|Compressed size|
|22|4|Uncompressed size|
|26|2|File name length (n)|
|28|2|Extra field length (m)|
|30|n|File Name|
|30+n|m|Extra Field|

其中`General purpose bit flag`为`00 00`时为未设置加密

故修改 06 和 47 位的`09`为`00`即可无密码进行解压获得`flag.txt`

进而获得`flag{Adm1N-B2G-kU-SZIP}`

### [Misc-\[BJDCTF2020\]鸡你太美](https://buuoj.cn/challenges#[BJDCTF2020]鸡你太美)

使用十六进制编辑器打开两个文件，对比发现`篮球副本.gif`文件头缺少`GIF8(47 49 46 38)`字样，添加后就能正常打开了，进而获得`flag{zhi_yin_you_are_beautiful}`

### [Misc-N种方法解决](https://buuoj.cn/challenges#N种方法解决)

下载获得`KEY.exe`文件，点击无法运行

使用Visual Studio Code打开，发现如下字样

```plain
data:image/jpg;base64,...
```

猜测是一个图片文件，后面的`...`为`base64`加密后的文件内容

使用[在线解密网站](https://the-x.cn/encodings/Base64.aspx)解密后保存为`png`文件，得到一个二维码

![[from_the-x.png]](./Notes-on-Misc/from_the-x.png)

扫描获得`KEY{dca57f966e4e4e31fd5b15417da63269}`

### [Misc-另外一个世界](https://buuoj.cn/challenges#另外一个世界)

解压后又是一个图片，用`Stegsolve`和`binwalk`都没看出什么异常

尝试用十六进制编辑器打开，在最底部发现一段不太寻常的01串

```plain
01101011 01101111 01100101 01101011 01101010 00110011 01110011
```

每8位转化为10进制($2^8-1=255$)并对应到ASCII码获得字符串

|二进制|十进制|ASCII|
|---|---|---|
|01101011|107|k|
|01101111|111|o|
|01100101|101|e|
|01101011|107|k|
|01101010|106|j|
|00110011|51|3|
|01110011|115|s|

获得`flag{koekj3s}`

### [Misc-wireshark](https://buuoj.cn/challenges#wireshark)

使用`wireshark`打开流量包

Ctrl + F打开过滤器，据题目提示，查找`POST`请求

运气很好，第一个`POST`请求就能获得`flag{ffb7567a1d4f4abdffdb54e022f8facd}`

![[Misc-wireshark.png]](./Notes-on-Misc/Misc-wireshark.png)

### [Misc-数据包中的线索](https://buuoj.cn/challenges#数据包中的线索)

直接查询`HTTP`

找到这条

![[Misc-数据包中的线索.png]](./Notes-on-Misc/Misc-数据包中的线索.png)

`右键 >> Follow >> HTTP Stream`，将内容复制下来通过`base64`解码得到一张图片

![[from_the-x.jpg]](./Notes-on-Misc/from_the-x.jpg)

获得`flag{209acebf6324a09671abc31c869de72c}`

### [Misc-文件中的秘密](https://buuoj.cn/challenges#文件中的秘密)

Windows下:

`右键 >> 属性(Alt + Ctrl) >> 详细信息 >> 备注` 获取 `flag{870c5a72806115cb5439345d8b014396}`

也可以用十六进制编辑器查找到相应片段

![[Misc-文件中的秘密.png]](./Notes-on-Misc/Misc-文件中的秘密.png)

### [Misc-FLAG](https://buuoj.cn/challenges#FLAG)

打开`Stegsolve`，使用`Analyse >> Data Extract`选中`Red 0, Green 0, Blue 0, LSB First`并`Save Bin`保存为zip文件并解压

执行`1`文件，可以找到`hctf{dd0gf4c3tok3yb0ard4g41n~~~}`字样

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/FLAG]
└─$ chmod +x 1

┌──(hervey㉿Hervey)-[~/Downloads/Misc/FLAG]
└─$ ./1
hctf{dd0gf4c3tok3yb0ard4g41n~~~}
```

或者用`strings`命令扫描文件

```bash
┌──(hervey㉿Hervey)-[~/Downloads/FLAG]
└─$ strings 1 | grep hctf
hctf{dd0gf4c3tok3yb0ard4g41n~~~}
```

或者用`ghidra`反编译二进制文件，找到`main`函数查看代码，发现

```cpp
void main(void)
{
  printf("hctf{dd0gf4c3tok3yb0ard4g41n~~~}");
  return;
}
```

都能获取`hctf{dd0gf4c3tok3yb0ard4g41n~~~}`

### [Misc-后门查杀](https://buuoj.cn/challenges#后门查杀)

将解压后的文件夹扔进D盾扫描

![[Misc-后门查杀-1.png]](./Notes-on-Misc/Misc-后门查杀-1.png)

点击`已知后门`，`右键 >> 查看文件`，找到如下字段，其中变量`pass`的内容为`md5`。

![[Misc-后门查杀-2.png]](./Notes-on-Misc/Misc-后门查杀-2.png)

依照提示进而获得`flag{6ac45fb83b3bc355c024f5034b947dd3}`

### [Misc-来首歌吧](https://buuoj.cn/challenges#来首歌吧)

使用`Audacity`打开解压后的音频文件`stego100`

放大音轨后感觉好像是摩斯电码？先把它抄下来

```plain
..... -... -.-. ----. ..--- ..... -.... ....- ----. -.-. -... ----- .---- ---.. ---.. ..-. ..... ..--- . -... .---- --... -.. --... ----- ----. ..--- ----. .---- ----. .---- -.-.
```

放到解密器里解密，获得`flag{5BC925649CB0188F52E617D70929191C}`

### [Misc-乌镇峰会种图](https://buuoj.cn/challenges#乌镇峰会种图)

思路同[Misc-你竟然赶我走](https://buuoj.cn/challenges#你竟然赶我走)

`flag{97314e7864a8f62627b26f3f998c37f1}`

### [Misc-基础破解](https://buuoj.cn/challenges#基础破解)

根据题目提示，我们使用`rarcrack`命令暴力破解下载获得的文件

首先设置`<filename>.xml`配置文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rarcrack>
  <abc>0123456789</abc>
  <current>0000</current>
  <good_password/>
</rarcrack>
```

再使用命令破解

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/基础破解]
└─$ rarcrack »ù´¡ÆÆ½â.rar --threads 20 --type rar
RarCrack! 0.2 by David Zoltan Kedves (kedazo@gmail.com)

INFO: number of threads adjusted to 12
INFO: the specified archive type: rar
INFO: cracking »ù´¡ÆÆ½â.rar, status file: »ù´¡ÆÆ½â.rar.xml
INFO: Resuming cracking from password: '0000'
GOOD: password cracked: '2563'
```

解压获得`flag.txt`

```plain
ZmxhZ3s3MDM1NDMwMGE1MTAwYmE3ODA2ODgwNTY2MWI5M2E1Y30=
```

尝试提交`flag`，发现错误

再次观察这段消息，或许是加密后的结果？

使用[在线解密网站](https://the-x.cn/encodings/Base64.aspx)解密，获取`flag{70354300a5100ba78068805661b93a5c}`

### [Misc-假如给我三天光明](https://buuoj.cn/challenges#假如给我三天光明)

解压文件，得到一个压缩文件`music.zip`和一张图片`pic.jpg`

打开图片，发现下面有一排 $2 \times 3$ 点阵图，猜测是盲文

查询盲文表并解密，得到`kmdonowg`

尝试以此为密码解压文件，发现解压不成功

通过`binwalk`指令扫描文件，提示这是一个`rar`文件

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/假如给我三天光明]
└─$ binwalk music.zip 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             RAR archive data, version 4.x, first volume type: MAIN_HEAD
```

将文件名改为`music.rar`，以`kmdonowg`为密码尝试再次解压

得到一个音频文件，使用`Audacity`打开文件，获得一段摩斯电码

```plain
-.-. - ..-. .-- .--. . .. ----- ---.. --... ...-- ..--- ..--.. ..--- ...-- -.. --..
```

通过摩斯电码转换器获得

```plain
CTFWPEI08732?23DZ
```

进而获得`flag{wepi08732?23dz}`

### [Misc-rar](https://buuoj.cn/challenges#rar)

根据题目提示，我们使用`rarcrack`命令暴力破解下载获得的文件

首先设置`<filename>.xml`配置文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rarcrack>
  <abc>0123456789</abc>
  <current>0000</current>
  <good_password/>
</rarcrack>
```

再使用命令破解

```bash
┌──(hervey㉿Hervey)-[~/Downloads/Misc/rar]
└─$ rarcrack dianli_jbctf_MISC_T10076_20150707_rar.rar --threads 20 --type rar
RarCrack! 0.2 by David Zoltan Kedves (kedazo@gmail.com)

INFO: number of threads adjusted to 12
INFO: the specified archive type: rar
INFO: cracking dianli_jbctf_MISC_T10076_20150707_rar.rar, status file: dianli_jbctf_MISC_T10076_20150707_rar.rar.xml
INFO: Resuming cracking from password: '0000'
Probing: '1488' [492 pwds/sec]
Probing: '3120' [544 pwds/sec]
Probing: '4724' [534 pwds/sec]
Probing: '6313' [529 pwds/sec]
Probing: '7947' [544 pwds/sec]
GOOD: password cracked: '8795'
```

解压获得`flag.txt`

```plain
flag{1773c5da790bd3caff38e3decd180eb7}
```
