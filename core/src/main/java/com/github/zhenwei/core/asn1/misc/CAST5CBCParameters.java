package com.github.zhenwei.core.asn1.misc;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.util.Arrays;

public class CAST5CBCParameters
    extends ASN1Object
{
    ASN1Integer keyLength;
    ASN1OctetString iv;

    public static misc.CAST5CBCParameters getInstance(
        Object  o)
    {
        if (o instanceof misc.CAST5CBCParameters)
        {
            return (misc.CAST5CBCParameters)o;
        }
        else if (o != null)
        {
            return new misc.CAST5CBCParameters(ASN1Sequence.getInstance(o));
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