package com.github.zhenwei.pkix.util.asn1.crmf;


import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;

public class Controls
    extends ASN1Object
{
    private ASN1Sequence content;

    private Controls(ASN1Sequence seq)
    {
        content = seq;
    }

    public static crmf.Controls getInstance(Object o)
    {
        if (o instanceof crmf.Controls)
        {
            return (crmf.Controls)o;
        }

        if (o != null)
        {
            return new crmf.Controls(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Controls(AttributeTypeAndValue atv)
    {
        content = new DERSequence(atv);
    }

    public Controls(AttributeTypeAndValue[] atvs)
    {
        content = new DERSequence(atvs);
    }

    public AttributeTypeAndValue[] toAttributeTypeAndValueArray()
    {
        AttributeTypeAndValue[] result = new AttributeTypeAndValue[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = AttributeTypeAndValue.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * Controls  ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}