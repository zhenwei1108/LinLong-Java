package com.github.zhenwei.pkix.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import java.math.BigInteger;

public class Uint8
    extends ASN1Object
{
    private final int value;

    public Uint8(int value)
    {
        this.value = verify(value);
    }

    public Uint8(BigInteger value)
    {
        this.value = value.intValue();
    }

    public static Uint8 getInstance(Object o)
    {
        if (o instanceof Uint8)
        {
            return (Uint8)o;
        }
        else
        {
            return new Uint8(ASN1Integer.getInstance(o).getValue());
        }
    }

    protected int verify(int value)
    {
        if (value < 0)
        {
            throw new IllegalArgumentException("Uint16 must be >= 0");
        }
        if (value > 0xFF)
        {
            throw new IllegalArgumentException("Uint16 must be <= 0xFF");
        }

        return value;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(value);
    }
}