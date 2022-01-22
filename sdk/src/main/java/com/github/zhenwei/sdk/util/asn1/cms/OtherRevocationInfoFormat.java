package com.github.zhenwei.sdk.util.asn1.cms;










/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.1">RFC 5652</a>: OtherRevocationInfoFormat object.
 * <p>
 * <pre>
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *      otherRevInfoFormat OBJECT IDENTIFIER,
 *      otherRevInfo ANY DEFINED BY otherRevInfoFormat }
 * </pre>
 */
public class OtherRevocationInfoFormat
    extends ASN1Object
{
    private ASN1ObjectIdentifier otherRevInfoFormat;
    private ASN1Encodable otherRevInfo;

    public OtherRevocationInfoFormat(
        ASN1ObjectIdentifier otherRevInfoFormat,
        ASN1Encodable otherRevInfo)
    {
        this.otherRevInfoFormat = otherRevInfoFormat;
        this.otherRevInfo = otherRevInfo;
    }

    private OtherRevocationInfoFormat(
        ASN1Sequence seq)
    {
        otherRevInfoFormat = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        otherRevInfo = seq.getObjectAt(1);
    }

    /**
     * Return a OtherRevocationInfoFormat object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static cms.OtherRevocationInfoFormat getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return a OtherRevocationInfoFormat object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link cms.OtherRevocationInfoFormat} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with OtherRevocationInfoFormat structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static cms.OtherRevocationInfoFormat getInstance(
        Object obj)
    {
        if (obj instanceof cms.OtherRevocationInfoFormat)
        {
            return (cms.OtherRevocationInfoFormat)obj;
        }
        
        if (obj != null)
        {
            return new cms.OtherRevocationInfoFormat(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }

    public ASN1ObjectIdentifier getInfoFormat()
    {
        return otherRevInfoFormat;
    }

    public ASN1Encodable getInfo()
    {
        return otherRevInfo;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(otherRevInfoFormat);
        v.add(otherRevInfo);

        return new DERSequence(v);
    }
}