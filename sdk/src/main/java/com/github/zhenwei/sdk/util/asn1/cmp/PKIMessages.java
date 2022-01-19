package com.github.zhenwei.sdk.util.asn1.cmp;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class PKIMessages
    extends ASN1Object
{
    private ASN1Sequence content;

    private PKIMessages(ASN1Sequence seq)
    {
        content = seq;
    }

    public static org.bouncycastle.asn1.cmp.PKIMessages getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cmp.PKIMessages)
        {
            return (org.bouncycastle.asn1.cmp.PKIMessages)o;
        }

        if (o != null)
        {
            return new org.bouncycastle.asn1.cmp.PKIMessages(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PKIMessages(PKIMessage msg)
    {
        content = new DERSequence(msg);
    }

    public PKIMessages(PKIMessage[] msgs)
    {
        content = new DERSequence(msgs);
    }

    public PKIMessage[] toPKIMessageArray()
    {
        PKIMessage[] result = new PKIMessage[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = PKIMessage.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}