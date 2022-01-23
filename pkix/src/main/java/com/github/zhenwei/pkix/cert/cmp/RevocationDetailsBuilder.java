package com.github.zhenwei.pkix.cert.cmp;



import cmp.RevDetails;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import crmf.CertTemplateBuilder;
import java.math.BigInteger;

public class RevocationDetailsBuilder
{
    private CertTemplateBuilder templateBuilder = new CertTemplateBuilder();
    
    public org.bouncycastle.cert.cmp.RevocationDetailsBuilder setPublicKey(
        SubjectPublicKeyInfo publicKey)
    {
        if (publicKey != null)
        {
            templateBuilder.setPublicKey(publicKey);
        }

        return this;
    }

    public org.bouncycastle.cert.cmp.RevocationDetailsBuilder setIssuer(X500Name issuer)
    {
        if (issuer != null)
        {
            templateBuilder.setIssuer(issuer);
        }

        return this;
    }

    public org.bouncycastle.cert.cmp.RevocationDetailsBuilder setSerialNumber(BigInteger serialNumber)
    {
        if (serialNumber != null)
        {
            templateBuilder.setSerialNumber(new ASN1Integer(serialNumber));
        }

        return this;
    }

    public org.bouncycastle.cert.cmp.RevocationDetailsBuilder setSubject(X500Name subject)
    {
        if (subject != null)
        {
            templateBuilder.setSubject(subject);
        }

        return this;
    }

    public RevocationDetails build()
    {
        return new RevocationDetails(new RevDetails(templateBuilder.build()));
    }
}