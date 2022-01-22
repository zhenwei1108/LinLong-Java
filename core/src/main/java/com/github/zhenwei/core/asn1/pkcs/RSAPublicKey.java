package com.github.zhenwei.core.asn1.pkcs;








import java.math.BigInteger;
import java.util.Enumeration;

public class RSAPublicKey
    extends ASN1Object
{
    private BigInteger modulus;
    private BigInteger publicExponent;

    public static pkcs.RSAPublicKey getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static pkcs.RSAPublicKey getInstance(
        Object obj)
    {
        if (obj instanceof pkcs.RSAPublicKey)
        {
            return (pkcs.RSAPublicKey)obj;
        }

        if (obj != null)
        {
            return new pkcs.RSAPublicKey(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }
    
    public RSAPublicKey(
        BigInteger modulus,
        BigInteger publicExponent)
    {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
    }

    private RSAPublicKey(
        ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        Enumeration e = seq.getObjects();

        modulus = ASN1Integer.getInstance(e.nextElement()).getPositiveValue();
        publicExponent = ASN1Integer.getInstance(e.nextElement()).getPositiveValue();
    }

    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getPublicExponent()
    {
        return publicExponent;
    }

    /**
     * This outputs the key in PKCS1v2 format.
     * <pre>
     *      RSAPublicKey ::= SEQUENCE {
     *                          modulus INTEGER, -- n
     *                          publicExponent INTEGER, -- e
     *                      }
     * </pre>
     * <p>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(new ASN1Integer(getModulus()));
        v.add(new ASN1Integer(getPublicExponent()));

        return new DERSequence(v);
    }
}