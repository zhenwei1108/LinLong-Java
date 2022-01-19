package com.github.zhenwei.core.asn1.oiw;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ElGamalParameter
    extends ASN1Object
{
    ASN1Integer      p, g;

    public ElGamalParameter(
        BigInteger  p,
        BigInteger  g)
    {
        this.p = new ASN1Integer(p);
        this.g = new ASN1Integer(g);
    }

    private ElGamalParameter(
        ASN1Sequence  seq)
    {
        Enumeration     e = seq.getObjects();

        p = (ASN1Integer)e.nextElement();
        g = (ASN1Integer)e.nextElement();
    }

    public static org.bouncycastle.asn1.oiw.ElGamalParameter getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.oiw.ElGamalParameter)
        {
            return (org.bouncycastle.asn1.oiw.ElGamalParameter)o;
        }
        else if (o != null)
        {
            return new org.bouncycastle.asn1.oiw.ElGamalParameter(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public BigInteger getP()
    {
        return p.getPositiveValue();
    }

    public BigInteger getG()
    {
        return g.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(p);
        v.add(g);

        return new DERSequence(v);
    }
}