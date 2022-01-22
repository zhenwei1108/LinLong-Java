package com.github.zhenwei.sdk.util.asn1.cms;


import DLSet;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;

/**
 * <a href="https://tools.ietf.org/html/rfc5652">RFC 5652</a> defines
 * 5 "SET OF Attribute" entities with 5 different names.
 * This is common implementation for them all:
 * <pre>
 *   SignedAttributes      ::= SET SIZE (1..MAX) OF Attribute
 *   UnsignedAttributes    ::= SET SIZE (1..MAX) OF Attribute
 *   UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *   AuthAttributes        ::= SET SIZE (1..MAX) OF Attribute
 *   UnauthAttributes      ::= SET SIZE (1..MAX) OF Attribute
 *
 * Attributes ::=
 *   SET SIZE(1..MAX) OF Attribute
 * </pre>
 */
public class Attributes
    extends ASN1Object
{
    private ASN1Set attributes;

    private Attributes(ASN1Set set)
    {
        attributes = set;
    }

    public Attributes(ASN1EncodableVector v)
    {
        attributes = new DLSet(v);
    }

    /**
     * Return an Attribute set object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link cms.Attributes} object
     * <li> {@link ASN1Set#getInstance(Object) ASN1Set} input formats with Attributes structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static cms.Attributes getInstance(Object obj)
    {
        if (obj instanceof cms.Attributes)
        {
            return (cms.Attributes)obj;
        }
        else if (obj != null)
        {
            return new cms.Attributes(ASN1Set.getInstance(obj));
        }

        return null;
    }

    public static cms.Attributes getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Set.getInstance(obj, explicit));
    }

    public Attribute[] getAttributes()
    {
        Attribute[] rv = new Attribute[attributes.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Attribute.getInstance(attributes.getObjectAt(i));
        }

        return rv;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return attributes;
    }
}