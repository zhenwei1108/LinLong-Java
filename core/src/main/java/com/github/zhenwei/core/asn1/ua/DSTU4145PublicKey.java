package com.github.zhenwei.core.asn1.ua;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
import org.bouncycastle.math.ec.ECPoint;

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

    public static org.bouncycastle.asn1.ua.DSTU4145PublicKey getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.ua.DSTU4145PublicKey)
        {
            return (org.bouncycastle.asn1.ua.DSTU4145PublicKey)obj;
        }

        if (obj != null)
        {
            return new org.bouncycastle.asn1.ua.DSTU4145PublicKey(ASN1OctetString.getInstance(obj));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return pubKey;
    }

}