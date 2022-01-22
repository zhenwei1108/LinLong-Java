package com.github.zhenwei.sdk.util.asn1.ess;


import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.DEROctetString;

public class ContentIdentifier
    extends ASN1Object
{
     ASN1OctetString value;

    public static ess.ContentIdentifier getInstance(Object o)
    {
        if (o instanceof ess.ContentIdentifier)
        {
            return (ess.ContentIdentifier) o;
        }
        else if (o != null)
        {
            return new ess.ContentIdentifier(ASN1OctetString.getInstance(o));
        }

        return null;
    }

    /**
     * Create from OCTET STRING whose octets represent the identifier.
     */
    private ContentIdentifier(
        ASN1OctetString value)
    {
        this.value = value;
    }

    /**
     * Create from byte array representing the identifier.
     */
    public ContentIdentifier(
        byte[] value)
    {
        this(new DEROctetString(value));
    }
    
    public ASN1OctetString getValue()
    {
        return value;
    }

    /**
     * The definition of ContentIdentifier is
     * <pre>
     * ContentIdentifier ::=  OCTET STRING
     * </pre>
     * id-aa-contentIdentifier OBJECT IDENTIFIER ::= { iso(1)
     *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *  smime(16) id-aa(2) 7 }
     */
    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }
}