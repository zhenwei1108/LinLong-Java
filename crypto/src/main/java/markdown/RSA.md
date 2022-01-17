#RSA算法


| 原语   | 说明                                                         |
| ------ | ------------------------------------------------------------ |
| (n, e) | RSA Public Key                                               |
| n      | the modulus                                                  |
| e      | the public exponent                                          |
| K      | RSA Private Key , 有两种表示方式 （n, d） 和（p,q dp, dq, qInv） |
| d      | the private exponent                                         |
| p      | the first factor                                             |
| q      | the second factor                                            |
| dP     | the first factor's exponent                                  |
| dQ     | the second factor's exponent                                 |
| qInv   | the CRT coefficient                                          |
|        |                                                              |

# 数学基础
## 1 整除
c = k1 * a + k2 * b , 且有一个数 e, 既可以整除a:  e|a,也可以整除b:  e|b,
则 e 一定可以整除c:  e|c. (e为公因子)
## 2 最大公约数(最大公因子)
a = k * b + c, (0 <= c <= b)
则 a和b的最大公因子 (a, b) = (b, c)
## 3 欧几里得算法(辗转相除法)
求 m, n的最大公因子:
当m = 0 , 则最大公因子为n.
当m != 0, 则等同 计算 n, m%n 的最大公因子
## 4 互素
当(a, b) = 1时,a和b互素.
使: k1 * a + k2 * b = (a ,b) = 1 ,两边同时mod b, 从而: (k1 * a) mod b = 1.
## 5 欧拉函数
φ(n): 小于n, 大于0, 与n互素 的数 的数量.
## 6 欧拉定理
若(a, n) = 1, 则 `a^[φ(n)] mod n = 1`.
## 7 欧拉定理推论
若 0 < a < n, (a, n) = 1
1. `a^[k * φ(n)] mod n = 1`
2. `a^[k * φ(n) + 1] mod n = a`
3. `a^ed mod n = a, ed mod φ(n) = 1 `
4. `(a^e mod n)^d mod n = a,  ed mod φ(n) = 1`
5. 若e,d不相等, 则 a^e mod n 为加密, 再 d 次幂后 mod n 为解密.e为私钥,d为公钥,a为原文

# 实现方式

1. 找到两个大数 p, q 两个正数互质。（*互质*是公约数只有1的两个整数）
2. n = p * q
3. 欧拉函数 φ(n) = (p-1) * (q-1)
4. 公钥： 找到e， 1<e<φ(n)， 且e和 φ(n) 互质
5. 私钥： 找到e*d除以φ(n)余1
6. 公钥加密： 原文m， m^e 除以n余c。 c为加密结果。
7. 私钥解密：c^d 除以n余m。 可得到原文m。
8. 数据签名：m^d 除以n余s。s为签名结果
9. 签名验签：s^e 除以n余m。