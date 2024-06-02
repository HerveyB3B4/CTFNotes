# Crypto 特训班 作业2 WriteUp

## 0 前置知识

1. RSA加密解密
2. SageMath , SymPy 和 gmpy2 中相关函数的的使用

## 1 过程记录

打开 `shall.py`

```python
from flag import text,flag
import md5
from Crypto.Util.number import long_to_bytes,bytes_to_long,getPrime

assert md5.new(text).hexdigest() == flag[6:-1]

msg1 = text[:xx]
msg2 = text[xx:yy]
msg3 = text[yy:]

msg1 = bytes_to_long(msg1)
msg2 = bytes_to_long(msg2)
msg3 = bytes_to_long(msg3)

p1 = getPrime(512)
q1 = getPrime(512)
N1 = p1*q1
e1 = 3
print pow(msg1,e1,N1)
print (e1,N1)

p2 = getPrime(512)
q2 = getPrime(512)
N2 = p2*q2
e2 = 17
e3 = 65537
print pow(msg2,e2,N2)
print pow(msg2,e3,N2)
print (e2,N2)
print (e3,N2)

p3 = getPrime(512)
q3 = getPrime(512)
N3 = p3*q3
print pow(msg3,e3,N3)
print (e3,N3)
print p3>>200
```

可以发现程序分为三部分，我们分开来看

### 1.1 Part1 RSA - 低加密指数攻击

首先看第一部分代码

```python
# Exp Part1
p1 = getPrime(512)
q1 = getPrime(512)
N1 = p1*q1
e1 = 3
print pow(msg1,e1,N1)
print (e1,N1)
```

可以发现 $e$ 很小，且密文 $msg_1$ 的 $e$ 次方小于模数 $N_1$，根据这些特点容易想到使用低加密指数攻击，直接对密文开立方即可获得明文

```python
c1 = int(content[0])
e1, N1 = map(int, content[1][1:-3].split(', '))

msg1 = long_to_bytes(gmpy2.iroot(c1, e1)[0])
print(msg1)
# b' \nO wild West Wind, thou breath of Autum'
```

### 1.2 Part2 RSA - 共模攻击

接下来看第二部分

```python
p2 = getPrime(512)
q2 = getPrime(512)
N2 = p2*q2
e2 = 17
e3 = 65537
print pow(msg2,e2,N2)
print pow(msg2,e3,N2)
print (e2,N2)
print (e3,N2)
```

可以发现两次 RSA 加密使用了相同的模数 $N_2$, 且指数 $e_2, e_3$ 互质，根据这些特点容易想到使用共模攻击

由两指数互质 $gcd(e_2, e_3) = 1 \Rightarrow e_2 \times s_2 + e_3 \times s_3 = 1$ ，使用扩展欧几里得算法可以求得 $s_2, s_3$


因为

$$
\begin{cases}
    c_2 \equiv m_2^{e_2} (mod \space N_2) \\
    c_3 \equiv m_2^{e_3} (mod \space N_2)
\end{cases}
$$

所以有

$$
    c_2^{d_2} \times c_3^{d3} \equiv (m_2^{e_2})^{s_2} \times (m_2^{e_3})^{s_3} \equiv m_2^{e_2 \times s_2 + e_3 \times s_3} (mod \space N_2)
$$

又

$$
    e_2 \times s_2 + e_3 \times s_3 = 1
$$

所以

$$
    c_2^{s_2} \times c_3^{s_3} \equiv m_2 (mod \space N_2)
$$

通过上述推导我们可以解出 $msg_2$

```python
# Exp Part2
c2 = int(content[2])
c3 = int(content[3])
e2, N2 = map(int, content[4][1:-3].split(', '))
e3, N2 = map(int, content[5][1:-3].split(', '))

d, s2, s3 = gmpy2.gcdext(e2, e3)
m2 = int(gmpy2.powmod(c2, s2, N2) * gmpy2.powmod(c3, s3, N2)) % N2
msg2 = long_to_bytes(m2)

print(msg2)
# b"n's being,\nThou, from whose unseen presence the leaves dead\nAre driven, like ghosts from an enchanter fleeing,\nYellow, a"
```

### 1.3 Part3 RSA - Coppersmith

```python
p3 = getPrime(512)
q3 = getPrime(512)
N3 = p3*q3
print pow(msg3,e3,N3)
print (e3,N3)
print p3>>200
```

题目给出了 $p_3$ 的前 $312$ 位(高位),可以使用 Coppersmith partial information attack 算法对 $p_3$ 的低位进行爆破解出 $p_3, q_3$

```python
from sage.all_cmdline import *   # import sage library
# Exp Part3
pbits = Integer(512) 

c4 = int(content[6])
e4, N3 = map(Integer, content[7][1:-3].split(', '))
pHigh = Integer(content[8])

kbits = pbits - pHigh.nbits()
pHigh = pHigh << kbits
PR = PolynomialRing(Zmod(N3), names=('x',)); (x,) = PR._first_ngens(1)
f = x + pHigh
roots = f.small_roots(X = Integer(2) ** kbits, beta = RealNumber('0.4') )
if roots:
    p3 = pHigh + int(roots[0])
    q3 = N3 / p3
    d3 = gmpy2.invert(e4, gmpy2.mpz(p3 - 1) * gmpy2.mpz(q3 - 1))
    m3 = gmpy2.powmod(c4, d3, N3)
    msg3 = long_to_bytes(m3)
    print(msg3)
    # b'nd black, and pale, and hectic red,\nPestilence-stricken multitudes: O thou,\nWho chariotest to their dark wintry bed\n'
```

得到 $msg$ 后进行 $MD5$ 进行信息摘要后获得 flag

总 exp :

```python
from Crypto.Util.number import long_to_bytes
from sage.all_cmdline import *   # import sage library
import hashlib
import gmpy2

f = open('out', 'r')
content = f.readlines()

# Exp Part1
c1 = int(content[0])
e1, N1 = map(int, content[1][1:-3].split(', '))

msg1 = long_to_bytes(gmpy2.iroot(c1, e1)[0])
print(msg1)
# b' \nO wild West Wind, thou breath of Autum'

# Exp Part2
c2 = int(content[2])
c3 = int(content[3])
e2, N2 = map(int, content[4][1:-3].split(', '))
e3, N2 = map(int, content[5][1:-3].split(', '))

d, s2, s3 = gmpy2.gcdext(e2, e3)
m2 = int(gmpy2.powmod(c2, s2, N2) * gmpy2.powmod(c3, s3, N2)) % N2
msg2 = long_to_bytes(m2)

print(msg2)
# b"n's being,\nThou, from whose unseen presence the leaves dead\nAre driven, like ghosts from an enchanter fleeing,\nYellow, a"

# Exp Part3
pbits = Integer(512) 

c4 = int(content[6])
e4, N3 = map(Integer, content[7][1:-3].split(', '))
pHigh = Integer(content[8])

kbits = pbits - pHigh.nbits()
pHigh = pHigh << kbits
PR = PolynomialRing(Zmod(N3), names=('x',)); (x,) = PR._first_ngens(1)
f = x + pHigh
roots = f.small_roots(X = Integer(2) ** kbits, beta = RealNumber('0.4') )
if roots:
    p3 = pHigh + int(roots[0])
    q3 = N3 / p3
    d3 = gmpy2.invert(e4, gmpy2.mpz(p3 - 1) * gmpy2.mpz(q3 - 1))
    m3 = gmpy2.powmod(c4, d3, N3)
    msg3 = long_to_bytes(m3)
    print(msg3)
    # b'nd black, and pale, and hectic red,\nPestilence-stricken multitudes: O thou,\nWho chariotest to their dark wintry bed\n'

msg = msg1 + msg2 + msg3
print(msg)
print(hashlib.md5(msg).hexdigest())
# 3943e8843a19149497956901e5d98639
```
