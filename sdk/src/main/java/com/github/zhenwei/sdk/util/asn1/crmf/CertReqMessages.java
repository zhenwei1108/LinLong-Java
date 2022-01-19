package com.github.zhenwei.sdk.util.asn1.crmf;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.CertReqMsg;

public class CertReqMessages
    extends ASN1Object
{
    private ASN1Sequence content;

    private CertReqMessages(ASN1Sequence seq)
    {
        content = seq;
    }

    public static org.bouncycastle.asn1.crmf.CertReqMessages getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.crmf.CertReqMessages)
        {
            return (org.bouncycastle.asn1.crmf.CertReqMessages)o;
        }

        if (o != null)
        {
            return new org.bouncycastle.asn1.crmf.CertReqMessages(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertReqMessages(
        CertReqMsg msg)
    {
        content = new DERSequence(msg);
    }

    public CertReqMessages(
        CertReqMsg[] msgs)
    {
        content = new DERSequence(msgs);
    }

    public CertReqMsg[] toCertReqMsgArray()
    {
        CertReqMsg[] result = new CertReqMsg[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = CertReqMsg.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}