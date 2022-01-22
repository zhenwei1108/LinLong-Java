package com.github.zhenwei.pkix.util.asn1.cmp;


import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;

public class POPODecKeyChallContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private POPODecKeyChallContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static cmp.POPODecKeyChallContent getInstance(Object o)
    {
        if (o instanceof cmp.POPODecKeyChallContent)
        {
            return (cmp.POPODecKeyChallContent)o;
        }

        if (o != null)
        {
            return new cmp.POPODecKeyChallContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Challenge[] toChallengeArray()
    {
        Challenge[] result = new Challenge[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = Challenge.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * POPODecKeyChallContent ::= SEQUENCE OF Challenge
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}