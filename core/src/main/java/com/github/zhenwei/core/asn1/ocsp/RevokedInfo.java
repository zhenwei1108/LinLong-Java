package com.github.zhenwei.core.asn1.ocsp;


import ASN1Enumerated;
import ASN1GeneralizedTime;




import CRLReason;



public class RevokedInfo
    extends ASN1Object
{
    private ASN1GeneralizedTime  revocationTime;
    private CRLReason           revocationReason;

    public RevokedInfo(
        ASN1GeneralizedTime  revocationTime,
        CRLReason           revocationReason)
    {
        this.revocationTime = revocationTime;
        this.revocationReason = revocationReason;
    }

    private RevokedInfo(
        ASN1Sequence    seq)
    {
        this.revocationTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            this.revocationReason = CRLReason.getInstance(ASN1Enumerated.getInstance(
                (ASN1TaggedObject)seq.getObjectAt(1), true));
        }
    }

    public static ocsp.RevokedInfo getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ocsp.RevokedInfo getInstance(
        Object  obj)
    {
        if (obj instanceof ocsp.RevokedInfo)
        {
            return (ocsp.RevokedInfo)obj;
        }
        else if (obj != null)
        {
            return new ocsp.RevokedInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1GeneralizedTime getRevocationTime()
    {
        return revocationTime;
    }

    public CRLReason getRevocationReason()
    {
        return revocationReason;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * RevokedInfo ::= SEQUENCE {
     *      revocationTime              GeneralizedTime,
     *      revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(revocationTime);
        if (revocationReason != null)
        {
            v.add(new DERTaggedObject(true, 0, revocationReason));
        }

        return new DERSequence(v);
    }
}