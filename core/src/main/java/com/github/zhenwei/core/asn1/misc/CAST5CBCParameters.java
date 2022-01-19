package com.github.zhenwei.core.asn1.misc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class CAST5CBCParameters
    extends ASN1Object
{
    ASN1Integer      keyLength;
    ASN1OctetString iv;

    public static org.bouncycastle.asn1.misc.CAST5CBCParameters getInstance(
        Object  o)
    {
        if (o instanceof org.bouncycastle.asn1.misc.CAST5CBCParameters)
        {
            return (org.bouncycastle.asn1.misc.CAST5CBCParameters)o;
        }
        else if (o != null)
        {
            return new org.bouncycastle.asn1.misc.CAST5CBCParameters(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CAST5CBCParameters(
        byte[]  iv,
        int     keyLength)
    {
        this.iv = new DEROctetString(Arrays.clone(iv));
        this.keyLength = new ASN1Integer(keyLength);
    }

    private CAST5CBCParameters(
        ASN1Sequence  seq)
    {
        iv = (ASN1OctetString)seq.getObjectAt(0);
        keyLength = (ASN1Integer)seq.getObjectAt(1);
    }

    public byte[] getIV()
    {
        return Arrays.clone(iv.getOctets());
    }

    public int getKeyLength()
    {
        return keyLength.intValueExact();
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * cast5CBCParameters ::= SEQUENCE {
     *                           iv         OCTET STRING DEFAULT 0,
     *                                  -- Initialization vector
     *                           keyLength  INTEGER
     *                                  -- Key length, in bits
     *                      }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(iv);
        v.add(keyLength);

        return new DERSequence(v);
    }
}