package com.github.zhenwei.sdk.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1Integer;
import java.math.BigInteger;

public class CountryOnly
    extends Uint16
    implements RegionInterface
{
    public CountryOnly(int value)
    {
        super(value);
    }

    public CountryOnly(BigInteger value)
    {
        super(value);
    }

    public static CountryOnly getInstance(Object o)
    {
        if (o instanceof CountryOnly)
        {
            return (CountryOnly)o;
        }
        else
        {
            return new CountryOnly(ASN1Integer.getInstance(o).getValue());
        }
    }
}