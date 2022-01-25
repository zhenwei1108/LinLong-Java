package com.github.zhenwei.pkix.cert.jcajce;

import com.github.zhenwei.core.asn1.x509.Certificate;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * JCA helper class for converting an X509Certificate into a X509CertificateHolder object.
 */
public class JcaX509CertificateHolder
    extends X509CertificateHolder {

  /**
   * Base constructor.
   *
   * @param cert certificate to be used a the source for the holder creation.
   * @throws CertificateEncodingException if there is a problem extracting the certificate
   *                                      information.
   */
  public JcaX509CertificateHolder(X509Certificate cert)
      throws CertificateEncodingException {
    super(Certificate.getInstance(cert.getEncoded()));
  }
}