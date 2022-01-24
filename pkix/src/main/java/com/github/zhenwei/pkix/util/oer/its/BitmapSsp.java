package com.github.zhenwei.pkix.util.oer.its;

import java.io.IOException;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.DEROctetString;

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