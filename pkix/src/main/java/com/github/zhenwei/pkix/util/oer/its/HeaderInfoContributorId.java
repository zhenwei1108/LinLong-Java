package com.github.zhenwei.pkix.util.oer.its;

import java.math.BigInteger;
import com.github.zhenwei.core.asn1.ASN1Integer;

public class HeaderInfoContributorId
    extends ASN1Integer
{

    public HeaderInfoContributorId(long value)
    {
        super(value);
    }

    public HeaderInfoContributorId(BigInteger value)
    {
        super(value);
    }

    public HeaderInfoContributorId(byte[] bytes)
    {
        super(bytes);
    }

    public static HeaderInfoContributorId getInstance(Object src)
    {
        if (src instanceof HeaderInfoContributorId)
        {
            return (HeaderInfoContributorId)src;
        }

        ASN1Integer integer = ASN1Integer.getInstance(src);
        return new HeaderInfoContributorId(integer.getValue());
    }


}