package com.github.zhenwei.sdk.util.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;

public class ProtectedPart
    extends ASN1Object
{
    private PKIHeader header;
    private PKIBody body;

    private ProtectedPart(ASN1Sequence seq)
    {
        header = PKIHeader.getInstance(seq.getObjectAt(0));
        body = PKIBody.getInstance(seq.getObjectAt(1));
    }

    public static org.bouncycastle.asn1.cmp.ProtectedPart getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cmp.ProtectedPart)
        {
            return (org.bouncycastle.asn1.cmp.ProtectedPart)o;
        }

        if (o != null)
        {
            return new org.bouncycastle.asn1.cmp.ProtectedPart(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ProtectedPart(PKIHeader header, PKIBody body)
    {
        this.header = header;
        this.body = body;
    }

    public PKIHeader getHeader()
    {
        return header;
    }

    public PKIBody getBody()
    {
        return body;
    }

    /**
     * <pre>
     * ProtectedPart ::= SEQUENCE {
     *                    header    PKIHeader,
     *                    body      PKIBody
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(header);
        v.add(body);

        return new DERSequence(v);
    }
}