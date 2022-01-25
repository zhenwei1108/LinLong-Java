package com.github.zhenwei.pkix.cert.ocsp.jcajce;

import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.pkix.cert.ocsp.BasicOCSPRespBuilder;
import com.github.zhenwei.pkix.cert.ocsp.OCSPException;
import com.github.zhenwei.pkix.operator.DigestCalculator;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;

public class JcaBasicOCSPRespBuilder
    extends BasicOCSPRespBuilder {

  public JcaBasicOCSPRespBuilder(X500Principal principal) {
    super(new JcaRespID(principal));
  }

  public JcaBasicOCSPRespBuilder(PublicKey key, DigestCalculator digCalc)
      throws OCSPException {
    super(SubjectPublicKeyInfo.getInstance(key.getEncoded()), digCalc);
  }
}