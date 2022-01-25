package com.github.zhenwei.pkix.cert.ocsp.jcajce;

import com.github.zhenwei.pkix.cert.jcajce.JcaX509CertificateHolder;
import com.github.zhenwei.pkix.cert.ocsp.CertificateID;
import com.github.zhenwei.pkix.cert.ocsp.OCSPException;
import com.github.zhenwei.pkix.operator.DigestCalculator;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class JcaCertificateID
    extends CertificateID {

  public JcaCertificateID(DigestCalculator digestCalculator, X509Certificate issuerCert,
      BigInteger number)
      throws OCSPException, CertificateEncodingException {
    super(digestCalculator, new JcaX509CertificateHolder(issuerCert), number);
  }
}