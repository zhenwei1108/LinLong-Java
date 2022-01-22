package com.github.zhenwei.sdk.util.asn1.esf;


import com.github.zhenwei.core.asn1.ASN1IA5String;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.DERIA5String;

public class SPuri
{
    private ASN1IA5String uri;

    public static esf.SPuri getInstance(
        Object obj)
    {
        if (obj instanceof esf.SPuri)
        {
            return (esf.SPuri) obj;
        }
        else if (obj instanceof ASN1IA5String)
        {
            return new esf.SPuri(ASN1IA5String.getInstance(obj));
        }

        return null;
    }

    public SPuri(
        ASN1IA5String uri)
    {
        this.uri = uri;
    }

    /**
     * @deprecated Use {@link #getUriIA5()} instead.
     */
    public DERIA5String getUri()
    {
        return null == uri || uri instanceof DERIA5String
            ?   (DERIA5String)uri
            :   new DERIA5String(uri.getString(), false);
    }

    public ASN1IA5String getUriIA5()
    {
        return uri;
    }

    /**
     * <pre>
     * SPuri ::= IA5String
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return uri.toASN1Primitive();
    }
}