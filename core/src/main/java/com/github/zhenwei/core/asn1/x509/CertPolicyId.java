package com.github.zhenwei.core.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;


/**
 * CertPolicyId, used in the CertificatePolicies and PolicyMappings
 * X509V3 Extensions.
 *
 * <pre>
 *     CertPolicyId ::= OBJECT IDENTIFIER
 * </pre>
 */

/**
 * CertPolicyId, used in the CertificatePolicies and PolicyMappings
 * X509V3 Extensions.
 *
 * <pre>
 *     CertPolicyId ::= OBJECT IDENTIFIER
 * </pre>
 */
public class CertPolicyId
    extends ASN1Object
{
    private ASN1ObjectIdentifier id;

    private CertPolicyId(ASN1ObjectIdentifier id)
    {
        this.id = id;
    }

    public static org.bouncycastle.asn1.x509.CertPolicyId getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.x509.CertPolicyId)
        {
            return (org.bouncycastle.asn1.x509.CertPolicyId)o;
        }
        else if (o != null)
        {
            return new org.bouncycastle.asn1.x509.CertPolicyId(ASN1ObjectIdentifier.getInstance(o));
        }

        return null;
    }

    public String getId()
    {
        return id.getId();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return id;
    }
}