package com.github.zhenwei.sdk.util.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;

public class GenMsgContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private GenMsgContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static org.bouncycastle.asn1.cmp.GenMsgContent getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cmp.GenMsgContent)
        {
            return (org.bouncycastle.asn1.cmp.GenMsgContent)o;
        }

        if (o != null)
        {
            return new org.bouncycastle.asn1.cmp.GenMsgContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public GenMsgContent(InfoTypeAndValue itv)
    {
        content = new DERSequence(itv);
    }

    public GenMsgContent(InfoTypeAndValue[] itvs)
    {
        content = new DERSequence(itvs);
    }

    public InfoTypeAndValue[] toInfoTypeAndValueArray()
    {
        InfoTypeAndValue[] result = new InfoTypeAndValue[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = InfoTypeAndValue.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}