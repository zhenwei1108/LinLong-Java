## 注意
1. 无法直接源码引用此包， 加载时会验证jar包中的签名。 需要使用jar包引用。 
2. 包签名： 建议使用验签的证书，并组装PKCS7，需要实验代码中是否验证pP7。
3. 核心实现类： javax.crypto.JarVerifier
4. 签名方式
```shell
        keytool -genkey -alias [别名] -keypass [密码]  -validity [有效期/天] -keystore [存储目录] -storepass [存储密码]  -dname [证书主题项/SubjectName]
        keytool -genkey -alias weGoo -keypass 123123  -validity 7200 -keystore C:\Users\zhenwei\Desktop\jamesKeyStore -storepass 123123  -dname "CN=JCE Code Signing CA, OU=Java Software Code Signing, O=Oracle Corporation"

        jarsigner -verbose -keystore [签名文件路径] -signedjar [签名后的apk文件路径] [未签名的apk文件路径] [证书别名]

        jarsigner -verbose -keystore C:\Users\zhenwei\Desktop\jamesKeyStore -signedjar  E:\mine-repo\com\github\zhenwei\provider\1.0.0-SNAPSHOT\provider-1.0.0-SNAPSHOT.jar   E:\mine-repo\com\github\zhenwei\provider\1.0.0-SNAPSHOT\provider-1.0.0-SNAPSHOT.jar weGoo



```



公钥为:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtHnThrc/eVDiE9rntyjpGEgE7VM/mT0TJ+0CCRNnvNptVNYdcj0Tv+QO63wv17EcpNp/qPDSU9gfMfT+d/0WZ8PSjPnqSEzG5H9cNCjJbPrTgelwrVISwvmsFrOqW5FaGhlHRwuwpExxB7VPeQDSEdlKCn+bRrIl320T9nRrzdgOHc15T4uGQbkoX9lmtFA8FU0QcEiqhxi7NPVuhyYZgix6z9+ZY+ZklQ38pa4BzrR9bkN4wza869SMS01rb1lRdt8bC6c5oIZ0uOdAd1PfS7wT17n22wBguPaqY0qcLnCIxQ6rmFH+xj1baTC014LZMVE3jV4+U96V8jQsuy1JlQIDAQAB
p10: MIICiTCCAXECAQAwRjELMAkGA1UEBhMCQ04xHjAcBgNVBAsMFUxpbmdMb25nIENvZGUgU2lnbmluZzEXMBUGA1UEAwwOd2VHb28gUHJvdmlkZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0edOGtz95UOIT2ue3KOkYSATtUz+ZPRMn7QIJE2e82m1U1h1yPRO/5A7rfC/XsRyk2n+o8NJT2B8x9P53/RZnw9KM+epITMbkf1w0KMls+tOB6XCtUhLC+awWs6pbkVoaGUdHC7CkTHEHtU95ANIR2UoKf5tGsiXfbRP2dGvN2A4dzXlPi4ZBuShf2Wa0UDwVTRBwSKqHGLs09W6HJhmCLHrP35lj5mSVDfylrgHOtH1uQ3jDNrzr1IxLTWtvWVF23xsLpzmghnS450B3U99LvBPXufbbAGC49qpjSpwucIjFDquYUf7GPVtpMLTXgtkxUTeNXj5T3pXyNCy7LUmVAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAHga/QGfWoU7pNtvNlT6SWZ+Dq8GhNdd15IKKWrXGugr1BjPMMWPpHNrrzZ/SWt2zOTV3gg7+7kpCH68qr9m8wDQo8g/7WHYREsoZmqnsCyTaOQdyTATCuZbh+xiyMzL0hTsVbzyFT/pplPsYb+QZFfEZR/oal9TX5DO9XI4rUkdZvfUb9Y8WbKPo7JcnC+P/ykigElajNfyHOVES77Pt4RUpa6dwwR3a21O7XK+5Rsu3kE2sGcZ316xRlmljl4lpKwkaUZ7dKTk2XdYs64MIWwQGBR5kExJK9aFKZbMbwrT56LN+0/RTnGoPzGlwaBVL8l4rFKbcd3TlmqRa5//Z0k=