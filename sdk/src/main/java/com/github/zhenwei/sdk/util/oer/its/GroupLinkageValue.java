package com.github.zhenwei.sdk.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;

/**
 * <pre>
 *     GroupLinkageValue ::= SEQUENCE {
 *         jValue OCTET STRING (SIZE(4))
 *         value OCTET STRING (SIZE(9))
 *     }
 * </pre>
 */
public class GroupLinkageValue
    extends ASN1Object
{
    private final ASN1OctetString jValue;
    private final ASN1OctetString value;

    private GroupLinkageValue(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("sequence not length 2");
        }

        jValue = ASN1OctetString.getInstance(seq.getObjectAt(0));
        value = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static GroupLinkageValue getInstance(Object src)
    {
        if (src instanceof GroupLinkageValue)
        {
            return (GroupLinkageValue)src;
        }
        else if (src != null)
        {
            return new GroupLinkageValue(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    public ASN1OctetString getjValue()
    {
        return jValue;
    }

    public ASN1OctetString getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(jValue, value);
    }
}