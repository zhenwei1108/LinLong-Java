package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.pkix.cms.KeyAgreeRecipientId;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

public class JceKeyAgreeRecipientId
    extends KeyAgreeRecipientId {

  public JceKeyAgreeRecipientId(X509Certificate certificate) {
    this(certificate.getIssuerX500Principal(), certificate.getSerialNumber());
  }

  public JceKeyAgreeRecipientId(X500Principal issuer, BigInteger serialNumber) {
    super(X500Name.getInstance(issuer.getEncoded()), serialNumber);
  }
}