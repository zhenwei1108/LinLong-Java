package com.github.zhenwei.core.asn1.pkcs;









import java.math.BigInteger;

public class PKCS12PBEParams
    extends ASN1Object
{
    ASN1Integer      iterations;
    ASN1OctetString iv;

    public PKCS12PBEParams(
        byte[]      salt,
        int         iterations)
    {
        this.iv = new DEROctetString(salt);
        this.iterations = new ASN1Integer(iterations);
    }

    private PKCS12PBEParams(
        ASN1Sequence  seq)
    {
        iv = (ASN1OctetString)seq.getObjectAt(0);
        iterations = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public static pkcs.PKCS12PBEParams getInstance(
        Object  obj)
    {
        if (obj instanceof pkcs.PKCS12PBEParams)
        {
            return (pkcs.PKCS12PBEParams)obj;
        }
        else if (obj != null)
        {
            return new pkcs.PKCS12PBEParams(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public BigInteger getIterations()
    {
        return iterations.getValue();
    }

    public byte[] getIV()
    {
        return iv.getOctets();
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(iv);
        v.add(iterations);

        return new DERSequence(v);
    }
}