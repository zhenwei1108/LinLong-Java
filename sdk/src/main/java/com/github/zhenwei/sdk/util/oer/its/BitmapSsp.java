package com.github.zhenwei.sdk.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.DEROctetString;
import java.io.IOException;

public class BitmapSsp
    extends DEROctetString
{
    public BitmapSsp(byte[] string)
    {
        super(string);
    }

    public BitmapSsp(ASN1Encodable obj)
        throws IOException
    {
        super(obj);
    }
}