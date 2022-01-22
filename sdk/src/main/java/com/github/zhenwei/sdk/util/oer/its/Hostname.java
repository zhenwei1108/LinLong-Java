package com.github.zhenwei.sdk.util.oer.its;






public class Hostname
    extends ASN1Object
{
    private final String hostName;


    public Hostname(String hostName)
    {
        this.hostName = hostName;
    }

    public static Hostname getInstance(Object src)
    {
        if (src instanceof Hostname)
        {
            return (Hostname)src;
        }

        if (src instanceof String)
        {
            return new Hostname((String)src);
        }

        if (src instanceof ASN1String)
        {
            return new Hostname(((ASN1String)src).getString());
        }

        throw new IllegalArgumentException("hostname accepts Hostname, String and ASN1String");

    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERUTF8String(hostName);
    }
}