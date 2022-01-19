package com.github.zhenwei.sdk.util.asn1.esf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.ResponderID;

/**
 * <pre>
 * OcspIdentifier ::= SEQUENCE {
 *     ocspResponderID ResponderID, -- As in OCSP response data
 *     producedAt GeneralizedTime -- As in OCSP response data
 * }
 * </pre>
 */
public class OcspIdentifier
    extends ASN1Object
{
    private ResponderID ocspResponderID;
    private ASN1GeneralizedTime producedAt;

    public static org.bouncycastle.asn1.esf.OcspIdentifier getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.esf.OcspIdentifier)
        {
            return (org.bouncycastle.asn1.esf.OcspIdentifier)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.esf.OcspIdentifier(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private OcspIdentifier(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        this.ocspResponderID = ResponderID.getInstance(seq.getObjectAt(0));
        this.producedAt = (ASN1GeneralizedTime)seq.getObjectAt(1);
    }

    public OcspIdentifier(ResponderID ocspResponderID, ASN1GeneralizedTime producedAt)
    {
        this.ocspResponderID = ocspResponderID;
        this.producedAt = producedAt;
    }

    public ResponderID getOcspResponderID()
    {
        return this.ocspResponderID;
    }

    public ASN1GeneralizedTime getProducedAt()
    {
        return this.producedAt;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.ocspResponderID);
        v.add(this.producedAt);
        return new DERSequence(v);
    }
}