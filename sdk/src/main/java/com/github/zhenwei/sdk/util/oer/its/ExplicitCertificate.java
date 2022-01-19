package com.github.zhenwei.sdk.util.oer.its;

import org.bouncycastle.asn1.ASN1Integer;

public class ExplicitCertificate
    extends CertificateBase
{
    public ExplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, CertificateType.Explicit, issuer, toBeSignedCertificate, signature);
    }

}