package com.github.zhenwei.core.asn1.ua;





 

public class DSTU4145PublicKey
    extends ASN1Object
{

    private ASN1OctetString pubKey;

    public DSTU4145PublicKey(ECPoint pubKey)
    {
        // We always use big-endian in parameter encoding
        this.pubKey = new DEROctetString(DSTU4145PointEncoder.encodePoint(pubKey));
    }

    private DSTU4145PublicKey(ASN1OctetString ocStr)
    {
        pubKey = ocStr;
    }

    public static ua.DSTU4145PublicKey getInstance(Object obj)
    {
        if (obj instanceof ua.DSTU4145PublicKey)
        {
            return (ua.DSTU4145PublicKey)obj;
        }

        if (obj != null)
        {
            return new ua.DSTU4145PublicKey(ASN1OctetString.getInstance(obj));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return pubKey;
    }

}