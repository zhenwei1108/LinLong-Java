package com.github.zhenwei.pkix.pkcs.jcajce;

import java.security.PrivateKey;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import pkcs.PrivateKeyInfo;

public class JcaPKCS8EncryptedPrivateKeyInfoBuilder
    extends PKCS8EncryptedPrivateKeyInfoBuilder
{
    public JcaPKCS8EncryptedPrivateKeyInfoBuilder(PrivateKey privateKey)
    {
         super(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
    }
}