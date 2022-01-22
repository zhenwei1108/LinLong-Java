package com.github.zhenwei.sdk.util.oer.its;



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