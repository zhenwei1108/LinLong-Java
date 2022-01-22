package com.github.zhenwei.sdk.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.DEROctetString;
import java.io.IOException;

/**
 * <pre>
 *     LinkageValue ::= OCTET STRING (SIZE(9))
 * </pre>
 */
public class LinkageValue
    extends DEROctetString
{


    public LinkageValue(byte[] string)
    {
        super(string);
    }

    public LinkageValue(ASN1Encodable obj)
        throws IOException
    {
        super(obj);
    }

    public static LinkageValue getInstance(Object src)
    {
        if (src instanceof LinkageValue)
        {
            return (LinkageValue)src;
        }
        else if (src != null)
        {
            return new LinkageValue(ASN1OctetString.getInstance(src).getOctets());
        }

        return null;
    }

}