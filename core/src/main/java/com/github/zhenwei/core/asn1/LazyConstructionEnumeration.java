package com.github.zhenwei.core.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.NoSuchElementException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ParsingException;

class LazyConstructionEnumeration
    implements Enumeration
{
    private ASN1InputStream aIn;
    private Object          nextObj;

    public LazyConstructionEnumeration(byte[] encoded)
    {
        aIn = new ASN1InputStream(encoded, true);
        nextObj = readObject();
    }

    public boolean hasMoreElements()
    {
        return nextObj != null;
    }

    public Object nextElement()
    {
        if (nextObj != null)
        {
            Object o = nextObj;
            nextObj = readObject();
            return o;
        }
        throw new NoSuchElementException();
    }

    private Object readObject()
    {
        try
        {
            return aIn.readObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException("malformed DER construction: " + e, e);
        }
    }
}