package com.github.zhenwei.sdk.util.asn1.esf;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;

public class SPuri
{
    private ASN1IA5String uri;

    public static org.bouncycastle.asn1.esf.SPuri getInstance(
        Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.esf.SPuri)
        {
            return (org.bouncycastle.asn1.esf.SPuri) obj;
        }
        else if (obj instanceof ASN1IA5String)
        {
            return new org.bouncycastle.asn1.esf.SPuri(ASN1IA5String.getInstance(obj));
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