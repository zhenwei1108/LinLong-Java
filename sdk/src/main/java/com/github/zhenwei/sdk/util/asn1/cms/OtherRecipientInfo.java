package com.github.zhenwei.sdk.util.asn1.cms;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.5">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * OtherRecipientInfo ::= SEQUENCE {
 *    oriType OBJECT IDENTIFIER,
 *    oriValue ANY DEFINED BY oriType }
 * </pre>
 */
public class OtherRecipientInfo
    extends ASN1Object
{
    private ASN1ObjectIdentifier oriType;
    private ASN1Encodable oriValue;

    public OtherRecipientInfo(
        ASN1ObjectIdentifier     oriType,
        ASN1Encodable            oriValue)
    {
        this.oriType = oriType;
        this.oriValue = oriValue;
    }
    
    private OtherRecipientInfo(
        ASN1Sequence seq)
    {
        oriType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        oriValue = seq.getObjectAt(1);
    }

    /**
     * Return a OtherRecipientInfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static cms.OtherRecipientInfo getInstance(
        ASN1TaggedObject obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return a OtherRecipientInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link PasswordRecipientInfo} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with OtherRecipientInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static cms.OtherRecipientInfo getInstance(
        Object obj)
    {
        if (obj instanceof cms.OtherRecipientInfo)
        {
            return (cms.OtherRecipientInfo)obj;
        }
        
        if (obj != null)
        {
            return new cms.OtherRecipientInfo(ASN1Sequence.getInstance(obj));
        }
        
        return null;
    }

    public ASN1ObjectIdentifier getType()
    {
        return oriType;
    }

    public ASN1Encodable getValue()
    {
        return oriValue;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(oriType);
        v.add(oriValue);

        return new DERSequence(v);
    }
}