package com.github.zhenwei.pkix.cert.crmf.jcajce;

import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.core.asn1.x509.GeneralName;
import com.github.zhenwei.pkix.cert.crmf.PKIArchiveControlBuilder;
import java.security.PrivateKey;
import javax.security.auth.x500.X500Principal;

public class JcaPKIArchiveControlBuilder
    extends PKIArchiveControlBuilder {

  public JcaPKIArchiveControlBuilder(PrivateKey privateKey, X500Name name) {
    this(privateKey, new GeneralName(name));
  }

  public JcaPKIArchiveControlBuilder(PrivateKey privateKey, X500Principal name) {
    this(privateKey, X500Name.getInstance(name.getEncoded()));
  }

  public JcaPKIArchiveControlBuilder(PrivateKey privateKey, GeneralName generalName) {
    super(PrivateKeyInfo.getInstance(privateKey.getEncoded()), generalName);
  }
}