package com.github.zhenwei.sdk.util.oer.its;



public class ExplicitCertificate
    extends CertificateBase
{
    public ExplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, CertificateType.Explicit, issuer, toBeSignedCertificate, signature);
    }

}