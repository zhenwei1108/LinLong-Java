package com.github.zhenwei.pkix.openssl.jcajce;

import java.security.PrivateKey;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.pkix.openssl.PKCS8Generator;
import  com.github.zhenwei.pkix.operator.OutputEncryptor;
import com.github.zhenwei.core.util.io.pem.PemGenerationException;

public class JcaPKCS8Generator
    extends PKCS8Generator
{
    public JcaPKCS8Generator(PrivateKey key, OutputEncryptor encryptor)
         throws PemGenerationException
    {
         super(PrivateKeyInfo.getInstance(key.getEncoded()), encryptor);
    }
}