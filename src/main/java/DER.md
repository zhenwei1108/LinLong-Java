[TOC]

# DER编码
* der编码是ber编码的子集.
* 是一个TLV结构.T:type(标签,标识), L:length(长度), V:value(值)


# Types
类型可以是直接编码的,或者包含其他构造的方式. 一下列举部分标签的列表

将类型使用二进制标识,从低到高编号 1-8

* 其中 8-7 表示

|      Class       | Value |                         Description                          |
| :--------------: | :---: | :----------------------------------------------------------: |
|    Universal     |   0   |                 The type is native to ASN.1                  |
|   Application    |   1   |     The type is only valid for one specific application      |
| Context-specific |   2   | Meaning of this type depends on the context (such as within a sequence, set or choice) |
|     Private      |   3   |              Defined in private specifications               |

* 其中 6 表示

|       P/C       | Value |                         Description                          |
| :-------------: | :---: | :----------------------------------------------------------: |
|  Primitive (P)  |   0   |    The contents octets directly encode the element value.    |
| Constructed (C) |   1   | The contents octets contain 0, 1, or more element encodings. |

* 其中 5-1 表示

|                             Name                             | Permitted Construction | Tag number Decimal| Tag number Hexadecimal     |
| :----------------------------------------------------------: | :--------------------: | :--------: | ---- |
|                     End-of-Content (EOC)                     |       Primitive        |     0      | 0    |
|                           BOOLEAN                            |       Primitive        |     1      | 1    |
|                           INTEGER                            |       Primitive        |     2      | 2    |
|                          BIT STRING                          |          Both          |     3      | 3    |
|                         OCTET STRING                         |          Both          |     4      | 4    |
|                             NULL                             |       Primitive        |     5      | 5    |
| [OBJECT IDENTIFIER](https://en.wikipedia.org/wiki/Object_identifier) |       Primitive        |     6      | 6    |
|                      Object Descriptor                       |          Both          |     7      | 7    |
|                           EXTERNAL                           |      Constructed       |     8      | 8    |
|                         REAL (float)                         |       Primitive        |     9      | 9    |
|                          ENUMERATED                          |       Primitive        |     10     | A    |
|                         EMBEDDED PDV                         |      Constructed       |     11     | B    |
|      [UTF8String](https://en.wikipedia.org/wiki/UTF-8)       |          Both          |     12     | C    |
|                         RELATIVE-OID                         |       Primitive        |     13     | D    |
|                             TIME                             |       Primitive        |     14     | E    |
|                           Reserved                           |                        |     15     | F    |
|                   SEQUENCE and SEQUENCE OF                   |      Constructed       |     16     | 10   |
|                        SET and SET OF                        |      Constructed       |     17     | 11   |
|                        NumericString                         |          Both          |     18     | 12   |
| [PrintableString](https://en.wikipedia.org/wiki/PrintableString) |          Both          |     19     | 13   |
|     [T61String](https://en.wikipedia.org/wiki/ITU_T.61)      |          Both          |     20     | 14   |
|                        VideotexString                        |          Both          |     21     | 15   |
|     [IA5String](https://en.wikipedia.org/wiki/IA5String)     |          Both          |     22     | 16   |
| [UTCTime](https://en.wikipedia.org/wiki/Coordinated_Universal_Time) |          Both          |     23     | 17   |
| [GeneralizedTime](https://en.wikipedia.org/wiki/GeneralizedTime) |          Both          |     24     | 18   |
|                        GraphicString                         |          Both          |     25     | 19   |
|                        VisibleString                         |          Both          |     26     | 1A   |
|                        GeneralString                         |          Both          |     27     | 1B   |
| [UniversalString](https://en.wikipedia.org/wiki/Universal_Character_Set) |          Both          |     28     | 1C   |
|                       CHARACTER STRING                       |      Constructed       |     29     | 1D   |
| [BMPString](https://en.wikipedia.org/wiki/Basic_Multilingual_Plane) |          Both          |     30     | 1E   |
|                             DATE                             |       Primitive        |     31     | 1F   |
|                         TIME-OF-DAY                          |       Primitive        |     32     | 20   |
|                          DATE-TIME                           |       Primitive        |     33     | 21   |
|                           DURATION                           |       Primitive        |     34     | 22   |
|                           OID-IRI                            |       Primitive        |     35     | 23   |
|                       RELATIVE-OID-IRI                       |       Primitive        |     36     | 24   |

# Length
分为长型编码和短型编码两种.
## 短型
用于
## 长型


#示例
RSA-PKCS1公钥

```
SEQUENCE (2 elem)
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1)
    NULL
  BIT STRING (1120 bit) 001100001000000110001001000000101000000110000001000000001110000010010…
    SEQUENCE (2 elem)
      INTEGER (1024 bit) 157703158759919915551173378062640511923046005515603145334821074853997…
      INTEGER 65537
```
共 162 字节
``` 
30 81 9F 30 0D 06 09 2A  86 48 86 F7 0D 01 01 01
05 00 03 81 8D 00 30 81  89 02 81 81 00 E0 93 A6
0F 32 AD C1 43 4B BA 8A  5C 75 1F 07 9A 24 BB 7F
05 3A 4C A6 48 0D 25 55  64 E8 B4 05 B6 9B 64 8E
9C E6 50 D3 7E 5E E3 04  12 84 45 41 F9 CB FC B7
90 1F 37 2E 4C C4 6C F8  92 3A A3 D6 74 1D 59 CF
59 17 47 35 22 87 F5 FC  9D 69 F3 C5 AB BF 25 FB
40 E9 71 6B 71 54 1C DB  B0 8B 02 38 1C 76 92 46
B2 8C CB C5 50 6A 94 39  69 D8 07 AA BD E9 D1 57
15 4D 35 95 F3 E7 C7 2A  96 66 36 BE EB 02 03 01
00 01 
```

其中
30 标识 type, 81 9F 标识 length, 后续为value
* 30 二进制表示为: 0011 0000, 其中第一个1标识Constructed (C), 第二个1标识 SEQUENCE
* 81 9F二进制表示为: 1000 0001 1001 1111, 81标识 9F标识后续长

本文引自: [wikipedia](https://en.wikipedia.org/wiki/X.690#DER_encoding)

