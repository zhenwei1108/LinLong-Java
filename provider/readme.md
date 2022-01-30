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