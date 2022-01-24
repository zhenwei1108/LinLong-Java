package com.github.zhenwei.pkix.util.oer.its;

import java.math.BigInteger;
import com.github.zhenwei.core.asn1.ASN1Integer;

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