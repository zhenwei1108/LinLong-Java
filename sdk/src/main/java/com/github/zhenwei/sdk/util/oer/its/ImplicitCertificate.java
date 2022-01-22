package com.github.zhenwei.sdk.util.oer.its;



public class ImplicitCertificate
    extends CertificateBase
{
    public ImplicitCertificate(ASN1Integer version, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, CertificateType.Implicit, issuer, toBeSignedCertificate, signature);
    }
}