package com.github.zhenwei.core.asn1.pkcs;


import X500Name;
import X509Name;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import java.math.BigInteger;

public class IssuerAndSerialNumber
    extends ASN1Object
{
    X500Name name;
    ASN1Integer certSerialNumber;

    public static IssuerAndSerialNumber getInstance(
        Object  obj)
    {
        if (obj instanceof IssuerAndSerialNumber)
        {
            return  (IssuerAndSerialNumber)obj;
        }
        else if (obj != null)
        {
            return new IssuerAndSerialNumber(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private IssuerAndSerialNumber(
        ASN1Sequence    seq)
    {
        this.name = X500Name.getInstance(seq.getObjectAt(0));
        this.certSerialNumber = (ASN1Integer)seq.getObjectAt(1);
    }

    public IssuerAndSerialNumber(
        X509Name    name,
        BigInteger  certSerialNumber)
    {
        this.name = X500Name.getInstance(name.toASN1Primitive());
        this.certSerialNumber = new ASN1Integer(certSerialNumber);
    }

    public IssuerAndSerialNumber(
        X509Name    name,
        ASN1Integer  certSerialNumber)
    {
        this.name = X500Name.getInstance(name.toASN1Primitive());
        this.certSerialNumber = certSerialNumber;
    }

    public IssuerAndSerialNumber(
        X500Name    name,
        BigInteger  certSerialNumber)
    {
        this.name = name;
        this.certSerialNumber = new ASN1Integer(certSerialNumber);
    }

    public X500Name getName()
    {
        return name;
    }

    public ASN1Integer getCertificateSerialNumber()
    {
        return certSerialNumber;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(name);
        v.add(certSerialNumber);

        return new DERSequence(v);
    }
}