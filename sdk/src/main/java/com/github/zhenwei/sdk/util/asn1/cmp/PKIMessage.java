package com.github.zhenwei.sdk.util.asn1.cmp;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERBitString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import java.util.Enumeration;

public class PKIMessage
    extends ASN1Object
{
    private PKIHeader header;
    private PKIBody body;
    private DERBitString protection;
    private ASN1Sequence extraCerts;

    private PKIMessage(ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();

        header = PKIHeader.getInstance(en.nextElement());
        body = PKIBody.getInstance(en.nextElement());

        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

            if (tObj.getTagNo() == 0)
            {
                protection = DERBitString.getInstance(tObj, true);
            }
            else
            {
                extraCerts = ASN1Sequence.getInstance(tObj, true);
            }
        }
    }

    public static cmp.PKIMessage getInstance(Object o)
    {
        if (o instanceof cmp.PKIMessage)
        {
            return (cmp.PKIMessage)o;
        }
        else if (o != null)
        {
            return new cmp.PKIMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * Creates a new PKIMessage.
     *
     * @param header     message header
     * @param body       message body
     * @param protection message protection (may be null)
     * @param extraCerts extra certificates (may be null)
     */
    public PKIMessage(
        PKIHeader header,
        PKIBody body,
        DERBitString protection,
        CMPCertificate[] extraCerts)
    {
        this.header = header;
        this.body = body;
        this.protection = protection;
        if (extraCerts != null)
        {
            this.extraCerts = new DERSequence(extraCerts);
        }
    }

    public PKIMessage(
        PKIHeader header,
        PKIBody body,
        DERBitString protection)
    {
        this(header, body, protection, null);
    }

    public PKIMessage(
        PKIHeader header,
        PKIBody body)
    {
        this(header, body, null, null);
    }

    public PKIHeader getHeader()
    {
        return header;
    }

    public PKIBody getBody()
    {
        return body;
    }

    public DERBitString getProtection()
    {
        return protection;
    }

    public CMPCertificate[] getExtraCerts()
    {
        if (extraCerts == null)
        {
            return null;
        }

        CMPCertificate[] results = new CMPCertificate[extraCerts.size()];

        for (int i = 0; i < results.length; i++)
        {
            results[i] = CMPCertificate.getInstance(extraCerts.getObjectAt(i));
        }
        return results;
    }

    /**
     * <pre>
     * PKIMessage ::= SEQUENCE {
     *                  header           PKIHeader,
     *                  body             PKIBody,
     *                  protection   [0] PKIProtection OPTIONAL,
     *                  extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                                                                     OPTIONAL
     * }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(header);
        v.add(body);

        addOptional(v, 0, protection);
        addOptional(v, 1, extraCerts);

        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}