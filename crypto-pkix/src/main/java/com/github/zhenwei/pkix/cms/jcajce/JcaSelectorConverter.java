package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.x500.X500Name;
import com.github.zhenwei.pkix.cms.KeyTransRecipientId;
import com.github.zhenwei.pkix.cms.SignerId;
import java.io.IOException;
import java.security.cert.X509CertSelector;

public class JcaSelectorConverter {

  public JcaSelectorConverter() {

  }

  public SignerId getSignerId(X509CertSelector certSelector) {
    try {
      if (certSelector.getSubjectKeyIdentifier() != null) {
        return new SignerId(X500Name.getInstance(certSelector.getIssuerAsBytes()),
            certSelector.getSerialNumber(),
            ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
      } else {
        return new SignerId(X500Name.getInstance(certSelector.getIssuerAsBytes()),
            certSelector.getSerialNumber());
      }
    } catch (IOException e) {
      throw new IllegalArgumentException("unable to convert issuer: " + e.getMessage());
    }
  }

  public KeyTransRecipientId getKeyTransRecipientId(X509CertSelector certSelector) {
    try {
      if (certSelector.getSubjectKeyIdentifier() != null) {
        return new KeyTransRecipientId(X500Name.getInstance(certSelector.getIssuerAsBytes()),
            certSelector.getSerialNumber(),
            ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
      } else {
        return new KeyTransRecipientId(X500Name.getInstance(certSelector.getIssuerAsBytes()),
            certSelector.getSerialNumber());
      }
    } catch (IOException e) {
      throw new IllegalArgumentException("unable to convert issuer: " + e.getMessage());
    }
  }
}