package com.github.zhenwei.sdk.util.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.7">RFC 5652</a>: OtherKeyAttribute object.
 * <p>
 * <pre>
 * OtherKeyAttribute ::= SEQUENCE {
 *     keyAttrId OBJECT IDENTIFIER,
 *     keyAttr ANY DEFINED BY keyAttrId OPTIONAL
 * }
 * </pre>
 */
public class OtherKeyAttribute
    extends ASN1Object
{
    private ASN1ObjectIdentifier keyAttrId;
    private ASN1Encodable        keyAttr;

    /**
     * Return an OtherKeyAttribute object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link org.bouncycastle.asn1.cms.OtherKeyAttribute} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with OtherKeyAttribute structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static org.bouncycastle.asn1.cms.OtherKeyAttribute getInstance(
        Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cms.OtherKeyAttribute)
        {
            return (org.bouncycastle.asn1.cms.OtherKeyAttribute)o;
        }
        
        if (o != null)
        {
            return new org.bouncycastle.asn1.cms.OtherKeyAttribute(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private OtherKeyAttribute(
        ASN1Sequence seq)
    {
        keyAttrId = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        keyAttr = seq.getObjectAt(1);
    }

    public OtherKeyAttribute(
        ASN1ObjectIdentifier keyAttrId,
        ASN1Encodable        keyAttr)
    {
        this.keyAttrId = keyAttrId;
        this.keyAttr = keyAttr;
    }

    public ASN1ObjectIdentifier getKeyAttrId()
    {
        return keyAttrId;
    }
    
    public ASN1Encodable getKeyAttr()
    {
        return keyAttr;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(keyAttrId);
        v.add(keyAttr);

        return new DERSequence(v);
    }
}