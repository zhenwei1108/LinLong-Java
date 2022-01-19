package com.github.zhenwei.sdk.util.asn1.esf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class OtherHashAlgAndValue
    extends ASN1Object
{
    private AlgorithmIdentifier hashAlgorithm;
    private ASN1OctetString     hashValue;


    public static org.bouncycastle.asn1.esf.OtherHashAlgAndValue getInstance(
        Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.esf.OtherHashAlgAndValue)
        {
            return (org.bouncycastle.asn1.esf.OtherHashAlgAndValue) obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.esf.OtherHashAlgAndValue(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private OtherHashAlgAndValue(
        ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        hashValue = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public OtherHashAlgAndValue(
        AlgorithmIdentifier hashAlgorithm,
        ASN1OctetString     hashValue)
    {
        this.hashAlgorithm = hashAlgorithm;
        this.hashValue = hashValue;
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }

    public ASN1OctetString getHashValue()
    {
        return hashValue;
    }

    /**
     * <pre>
     * OtherHashAlgAndValue ::= SEQUENCE {
     *     hashAlgorithm AlgorithmIdentifier,
     *     hashValue OtherHashValue }
     *
     * OtherHashValue ::= OCTET STRING
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(hashAlgorithm);
        v.add(hashValue);

        return new DERSequence(v);
    }
}