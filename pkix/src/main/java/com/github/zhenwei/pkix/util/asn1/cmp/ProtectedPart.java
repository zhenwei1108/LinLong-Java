package com.github.zhenwei.pkix.util.asn1.cmp;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;

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

    public static cmp.ProtectedPart getInstance(Object o)
    {
        if (o instanceof cmp.ProtectedPart)
        {
            return (cmp.ProtectedPart)o;
        }

        if (o != null)
        {
            return new cmp.ProtectedPart(ASN1Sequence.getInstance(o));
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