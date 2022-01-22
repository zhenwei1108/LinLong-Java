package com.github.zhenwei.core.asn1.sec;














import java.math.BigInteger;
import java.util.Enumeration;
 

/**
 * the elliptic curve private key object from SEC 1
 */
public class ECPrivateKey
    extends ASN1Object
{
    private ASN1Sequence seq;

    private ECPrivateKey(
        ASN1Sequence seq)
    {
        this.seq = seq;
    }

    public static sec.ECPrivateKey getInstance(
        Object obj)
    {
        if (obj instanceof sec.ECPrivateKey)
        {
            return (sec.ECPrivateKey)obj;
        }

        if (obj != null)
        {
            return new sec.ECPrivateKey(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * @deprecated use constructor which takes orderBitLength to guarantee correct encoding.
     */
    public ECPrivateKey(
        BigInteger key)
    {
        this(key.bitLength(), key);
    }

    /**
     * Base constructor.
     *
     * @param orderBitLength the bitLength of the order of the curve.
     * @param key the private key value.
     */
    public ECPrivateKey(
        int        orderBitLength,
        BigInteger key)
    {
        byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);

        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));

        seq = new DERSequence(v);
    }

    /**
     * @deprecated use constructor which takes orderBitLength to guarantee correct encoding.
     */
    public ECPrivateKey(
        BigInteger key,
        ASN1Encodable parameters)
    {
        this(key, null, parameters);
    }

    /**
     * @deprecated use constructor which takes orderBitLength to guarantee correct encoding.
     */
    public ECPrivateKey(
        BigInteger key,
        DERBitString publicKey,
        ASN1Encodable parameters)
    {
        this(key.bitLength(), key, publicKey, parameters);
    }

    public ECPrivateKey(
        int orderBitLength,
        BigInteger key,
        ASN1Encodable parameters)
    {
        this(orderBitLength, key, null, parameters);
    }

    public ECPrivateKey(
        int orderBitLength,
        BigInteger key,
        DERBitString publicKey,
        ASN1Encodable parameters)
    {
        byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);

        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));

        if (parameters != null)
        {
            v.add(new DERTaggedObject(true, 0, parameters));
        }

        if (publicKey != null)
        {
            v.add(new DERTaggedObject(true, 1, publicKey));
        }

        seq = new DERSequence(v);
    }

    public BigInteger getKey()
    {
        ASN1OctetString octs = (ASN1OctetString)seq.getObjectAt(1);

        return new BigInteger(1, octs.getOctets());
    }

    // TODO Make this ASN1BitString
    public DERBitString getPublicKey()
    {
        return (DERBitString)getObjectInTag(1, BERTags.BIT_STRING);
    }

    /**
     * @deprecated Use {@link #getParametersObject()} instead and getInstance
     *             methods or similar to get the object at the desired type.
     */
    public ASN1Primitive getParameters()
    {
        return getParametersObject().toASN1Primitive();
    }

    public ASN1Object getParametersObject()
    {
        return getObjectInTag(0, -1);
    }

    private ASN1Object getObjectInTag(int tagNo, int baseTagNo)
    {
        Enumeration e = seq.getObjects();

        while (e.hasMoreElements())
        {
            ASN1Encodable obj = (ASN1Encodable)e.nextElement();

            if (obj instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject tag = (ASN1TaggedObject)obj;
                if (tag.hasContextTag(tagNo))
                {
                    return baseTagNo < 0
                        ?   tag.getExplicitBaseObject().toASN1Primitive()
                        :   tag.getBaseUniversal(true, baseTagNo);
                }
            }
        }
        return null;
    }

    /**
     * ECPrivateKey ::= SEQUENCE {
     *     version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *     privateKey OCTET STRING,
     *     parameters [0] Parameters OPTIONAL,
     *     publicKey [1] BIT STRING OPTIONAL }
     */
    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}