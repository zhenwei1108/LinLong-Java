package com.github.zhenwei.sdk.util.asn1.esf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.esf.OcspIdentifier;
import org.bouncycastle.asn1.esf.OtherHash;

/**
 * <pre>
 * OcspResponsesID ::= SEQUENCE {
 *    ocspIdentifier OcspIdentifier,
 *    ocspRepHash OtherHash OPTIONAL
 * }
 * </pre>
 */
public class OcspResponsesID
    extends ASN1Object
{

    private OcspIdentifier ocspIdentifier;
    private OtherHash ocspRepHash;

    public static org.bouncycastle.asn1.esf.OcspResponsesID getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.esf.OcspResponsesID)
        {
            return (org.bouncycastle.asn1.esf.OcspResponsesID)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.esf.OcspResponsesID(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private OcspResponsesID(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        this.ocspIdentifier = OcspIdentifier.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1)
        {
            this.ocspRepHash = OtherHash.getInstance(seq.getObjectAt(1));
        }
    }

    public OcspResponsesID(OcspIdentifier ocspIdentifier)
    {
        this(ocspIdentifier, null);
    }

    public OcspResponsesID(OcspIdentifier ocspIdentifier, OtherHash ocspRepHash)
    {
        this.ocspIdentifier = ocspIdentifier;
        this.ocspRepHash = ocspRepHash;
    }

    public OcspIdentifier getOcspIdentifier()
    {
        return this.ocspIdentifier;
    }

    public OtherHash getOcspRepHash()
    {
        return this.ocspRepHash;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.ocspIdentifier);
        if (null != this.ocspRepHash)
        {
            v.add(this.ocspRepHash);
        }
        return new DERSequence(v);
    }
}