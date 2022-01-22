package com.github.zhenwei.sdk.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1Integer;
import java.math.BigInteger;

/**
 * CrlSeries ::= Uint16
 */
public class CrlSeries
    extends Uint16
{
    public CrlSeries(int value)
    {
        super(value);
    }

    public CrlSeries(BigInteger value)
    {
        super(value);
    }

    public static CrlSeries getInstance(Object o)
    {
        if (o instanceof CrlSeries)
        {
            return (CrlSeries)o;
        }
        return new CrlSeries(ASN1Integer.getInstance(o).getValue());
    }
}