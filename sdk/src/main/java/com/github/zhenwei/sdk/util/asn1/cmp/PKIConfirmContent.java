package com.github.zhenwei.sdk.util.asn1.cmp;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;

public class PKIConfirmContent
    extends ASN1Object
{
    private ASN1Null val;

    private PKIConfirmContent(ASN1Null val)
    {
        this.val = val;
    }

    public static org.bouncycastle.asn1.cmp.PKIConfirmContent getInstance(Object o)
    {
        if (o == null || o instanceof org.bouncycastle.asn1.cmp.PKIConfirmContent)
        {
            return (org.bouncycastle.asn1.cmp.PKIConfirmContent)o;
        }

        if (o instanceof ASN1Null)
        {
            return new org.bouncycastle.asn1.cmp.PKIConfirmContent((ASN1Null)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public PKIConfirmContent()
    {
        val = DERNull.INSTANCE;
    }

    /**
     * <pre>
     * PKIConfirmContent ::= NULL
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return val;
    }
}