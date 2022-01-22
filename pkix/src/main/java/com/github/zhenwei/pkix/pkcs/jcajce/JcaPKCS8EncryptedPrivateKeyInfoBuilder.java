package com.github.zhenwei.pkix.pkcs.jcajce;

import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import java.security.PrivateKey;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
 

public class JcaPKCS8EncryptedPrivateKeyInfoBuilder
    extends PKCS8EncryptedPrivateKeyInfoBuilder
{
    public JcaPKCS8EncryptedPrivateKeyInfoBuilder(PrivateKey privateKey)
    {
         super(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
    }
}