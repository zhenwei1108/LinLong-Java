package com.github.zhenwei.sdk.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1Integer;
import java.math.BigInteger;

public class PduFunctionType
    extends ASN1Integer
{

    public static final PduFunctionType tlsHandshake = new PduFunctionType(1);
    public static final PduFunctionType iso21177ExtendedAuth = new PduFunctionType(2);


    public PduFunctionType(long value)
    {
        super(value);
    }


    public PduFunctionType(BigInteger value)
    {
        super(value);
    }

    public PduFunctionType(byte[] bytes)
    {
        super(bytes);
    }

    public static PduFunctionType getInstance(Object src)
    {
        if (src instanceof PduFunctionType)
        {
            return (PduFunctionType)src;
        }
        else if (src instanceof ASN1Integer)
        {
            return new PduFunctionType(((ASN1Integer)src).getValue());
        }
        else
        {
            ASN1Integer in = ASN1Integer.getInstance(src);
            return getInstance(in);
        }
    }
}