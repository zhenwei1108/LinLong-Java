package com.github.zhenwei.sdk.util.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.CertStatus;

public class CertConfirmContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private CertConfirmContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static org.bouncycastle.asn1.cmp.CertConfirmContent getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cmp.CertConfirmContent)
        {
            return (org.bouncycastle.asn1.cmp.CertConfirmContent)o;
        }

        if (o != null)
        {
            return new org.bouncycastle.asn1.cmp.CertConfirmContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertStatus[] toCertStatusArray()
    {
        CertStatus[] result = new CertStatus[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = CertStatus.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * CertConfirmContent ::= SEQUENCE OF CertStatus
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}