package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Integer;

public class ImplicitCertificate
    extends CertificateBase {

  public ImplicitCertificate(ASN1Integer version, IssuerIdentifier issuer,
      ToBeSignedCertificate toBeSignedCertificate, Signature signature) {
    super(version, CertificateType.Implicit, issuer, toBeSignedCertificate, signature);
  }
}