package com.github.zhenwei.core.asn1;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class DERGraphicString
    extends ASN1GraphicString
{
    /**
     * return a Graphic String from the passed in object
     *
     * @param obj a DERGraphicString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERGraphicString instance, or null.
     * 
     * @deprecated Use {@link ASN1GraphicString#getInstance(Object)} instead.
     */
    public static org.bouncycastle.asn1.DERGraphicString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof org.bouncycastle.asn1.DERGraphicString)
        {
            return (org.bouncycastle.asn1.DERGraphicString)obj;
        }
        if (obj instanceof ASN1GraphicString)
        {
            return new org.bouncycastle.asn1.DERGraphicString(((ASN1GraphicString)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (org.bouncycastle.asn1.DERGraphicString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Graphic String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERGraphicString instance, or null.
     * 
     * @deprecated Use
     *             {@link ASN1GraphicString#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static org.bouncycastle.asn1.DERGraphicString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof org.bouncycastle.asn1.DERGraphicString)
        {
            return getInstance(o);
        }
        else
        {
            return new org.bouncycastle.asn1.DERGraphicString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    public DERGraphicString(byte[] octets)
    {
        this(octets, true);
    }

    DERGraphicString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}