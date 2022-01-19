package com.github.zhenwei.core.asn1.x509;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class DSAParameter
    extends ASN1Object
{
    ASN1Integer      p, q, g;

    public static org.bouncycastle.asn1.x509.DSAParameter getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static org.bouncycastle.asn1.x509.DSAParameter getInstance(
        Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.x509.DSAParameter)
        {
            return (org.bouncycastle.asn1.x509.DSAParameter)obj;
        }
        
        if(obj != null)
        {
            return new org.bouncycastle.asn1.x509.DSAParameter(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }

    public DSAParameter(
        BigInteger  p,
        BigInteger  q,
        BigInteger  g)
    {
        this.p = new ASN1Integer(p);
        this.q = new ASN1Integer(q);
        this.g = new ASN1Integer(g);
    }

    private DSAParameter(
        ASN1Sequence  seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        
        Enumeration     e = seq.getObjects();

        p = ASN1Integer.getInstance(e.nextElement());
        q = ASN1Integer.getInstance(e.nextElement());
        g = ASN1Integer.getInstance(e.nextElement());
    }

    public BigInteger getP()
    {
        return p.getPositiveValue();
    }

    public BigInteger getQ()
    {
        return q.getPositiveValue();
    }

    public BigInteger getG()
    {
        return g.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(p);
        v.add(q);
        v.add(g);

        return new DERSequence(v);
    }
}