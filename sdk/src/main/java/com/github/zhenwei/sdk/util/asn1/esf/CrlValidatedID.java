package com.github.zhenwei.sdk.util.asn1.esf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.OtherHash;

/**
 * <pre>
 * CrlValidatedID ::= SEQUENCE {
 *   crlHash OtherHash,
 *   crlIdentifier CrlIdentifier OPTIONAL }
 * </pre>
 */
public class CrlValidatedID
    extends ASN1Object
{

    private OtherHash crlHash;
    private CrlIdentifier crlIdentifier;

    public static org.bouncycastle.asn1.esf.CrlValidatedID getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.esf.CrlValidatedID)
        {
            return (org.bouncycastle.asn1.esf.CrlValidatedID)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.esf.CrlValidatedID(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private CrlValidatedID(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        this.crlHash = OtherHash.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1)
        {
            this.crlIdentifier = CrlIdentifier.getInstance(seq.getObjectAt(1));
        }
    }

    public CrlValidatedID(OtherHash crlHash)
    {
        this(crlHash, null);
    }

    public CrlValidatedID(OtherHash crlHash, CrlIdentifier crlIdentifier)
    {
        this.crlHash = crlHash;
        this.crlIdentifier = crlIdentifier;
    }

    public OtherHash getCrlHash()
    {
        return this.crlHash;
    }

    public CrlIdentifier getCrlIdentifier()
    {
        return this.crlIdentifier;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.crlHash.toASN1Primitive());
        if (null != this.crlIdentifier)
        {
            v.add(this.crlIdentifier.toASN1Primitive());
        }
        return new DERSequence(v);
    }
}