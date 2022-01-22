package com.github.zhenwei.pkix.util.asn1.cmc;


import ASN1GeneralizedTime;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.util.Arrays;


/**
 * <pre>
 * PendInfo ::= SEQUENCE {
 *    pendToken        OCTET STRING,
 *    pendTime         GeneralizedTime
 * }
 * </pre>
 */
public class PendInfo
    extends ASN1Object
{
    private final byte[] pendToken;
    private final ASN1GeneralizedTime pendTime;

    public PendInfo(byte[] pendToken, ASN1GeneralizedTime pendTime)
    {
        this.pendToken = Arrays.clone(pendToken);
        this.pendTime = pendTime;
    }

    private PendInfo(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.pendToken = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
        this.pendTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
    }

    public static cmc.PendInfo getInstance(Object o)
    {
        if (o instanceof cmc.PendInfo)
        {
            return (cmc.PendInfo)o;
        }

        if (o != null)
        {
            return new cmc.PendInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(new DEROctetString(pendToken));
        v.add(pendTime);

        return new DERSequence(v);
    }

    public byte[] getPendToken()
    {
        return Arrays.clone(pendToken);
    }

    public ASN1GeneralizedTime getPendTime()
    {
        return pendTime;
    }
}