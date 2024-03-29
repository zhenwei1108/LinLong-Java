package com.github.zhenwei.pkix.cert.selector.jcajce;

import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.pkix.cert.selector.X509CertificateHolderSelector;
import java.io.IOException;
import java.security.cert.X509CertSelector;

public class JcaSelectorConverter {

  public JcaSelectorConverter() {

  }

  public X509CertificateHolderSelector getCertificateHolderSelector(X509CertSelector certSelector) {
    try {
      if (certSelector.getSubjectKeyIdentifier() != null) {
        return new X509CertificateHolderSelector(
            X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber(),
            ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
      } else {
        return new X509CertificateHolderSelector(
            X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber());
      }
    } catch (IOException e) {
      throw new IllegalArgumentException("unable to convert issuer: " + e.getMessage());
    }
  }
}