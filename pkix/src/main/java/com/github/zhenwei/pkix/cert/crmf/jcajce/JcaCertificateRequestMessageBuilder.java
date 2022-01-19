package com.github.zhenwei.pkix.cert.crmf.jcajce;

import java.math.BigInteger;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;

public class JcaCertificateRequestMessageBuilder
    extends CertificateRequestMessageBuilder
{
    public JcaCertificateRequestMessageBuilder(BigInteger certReqId)
    {
        super(certReqId);
    }

    public org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder setIssuer(X500Principal issuer)
    {
        if (issuer != null)
        {
            setIssuer(X500Name.getInstance(issuer.getEncoded()));
        }

        return this;
    }

    public org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder setSubject(X500Principal subject)
    {
        if (subject != null)
        {
            setSubject(X500Name.getInstance(subject.getEncoded()));
        }

        return this;
    }

    public org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder setAuthInfoSender(X500Principal sender)
    {
        if (sender != null)
        {
            setAuthInfoSender(new GeneralName(X500Name.getInstance(sender.getEncoded())));
        }

        return this;
    }

    public org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder setPublicKey(PublicKey publicKey)
    {
        setPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));

        return this;
    }
}