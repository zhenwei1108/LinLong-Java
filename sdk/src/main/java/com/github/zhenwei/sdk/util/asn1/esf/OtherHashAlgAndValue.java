package com.github.zhenwei.sdk.util.asn1.esf;









public class OtherHashAlgAndValue
    extends ASN1Object
{
    private AlgorithmIdentifier hashAlgorithm;
    private ASN1OctetString     hashValue;


    public static esf.OtherHashAlgAndValue getInstance(
        Object obj)
    {
        if (obj instanceof esf.OtherHashAlgAndValue)
        {
            return (esf.OtherHashAlgAndValue) obj;
        }
        else if (obj != null)
        {
            return new esf.OtherHashAlgAndValue(ASN1Sequence.getInstance(obj));
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