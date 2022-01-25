# LinLong - 玲珑

基于BC做点有意思的,顺道学习巩固

## 说明

参考如下进行实现

```xml
		<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on -->
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>bcprov-jdk15on</artifactId>
			<version>${bouncycastle.bcprov.verion}</version>
		</dependency>

		<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on -->
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>bcpkix-jdk15on</artifactId>
			<version>${bouncycastle.bcpkix.verion}</version>
		</dependency>

		<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk16 -->
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>bcprov-jdk16</artifactId>
			<version>${bouncycastle.bcprov.jdk16.verion}</version>
		</dependency>

```

## 内容应包含

```
密钥创建: 常用算法的实现原理和方式
加解密: 常用算法加解密原理
签名验签: 常用算法的签名原理
摘要: ...
MAC(HMAC)
密钥协商
密钥派生
证书组装
密钥共享
FPE(保留格式加密format preserving encryption, FF1,FF3)
...
```

多学点?

```

多方安全计算
同态加密
零知识证明
零信任

```

## 参考

* https://github.com/google/tink
* https://github.com/cossacklabs/themis
* https://github.com/bcgit/bc-java

# 注:

1. BC使用对称加解密,有长度限制. 可以替换jre/security下面的包