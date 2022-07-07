package com.github.zhenwei.pkix.pkcs.jcajce;

import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.pkix.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import java.security.PrivateKey;

public class JcaPKCS8EncryptedPrivateKeyInfoBuilder
    extends PKCS8EncryptedPrivateKeyInfoBuilder {

  public JcaPKCS8EncryptedPrivateKeyInfoBuilder(PrivateKey privateKey) {
    super(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
  }
}