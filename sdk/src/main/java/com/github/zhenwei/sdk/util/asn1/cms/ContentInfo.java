package com.github.zhenwei.sdk.util.asn1.cms;









import BERTaggedObject;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> ContentInfo, and
 * <a href="https://tools.ietf.org/html/rfc5652#section-5.2">RFC 5652</a> EncapsulatedContentInfo objects.
 *
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * EncapsulatedContentInfo ::= SEQUENCE {
 *     eContentType ContentType,
 *     eContent [0] EXPLICIT OCTET STRING OPTIONAL
 * }
 * </pre>
 */
public class ContentInfo
    extends ASN1Object
    implements CMSObjectIdentifiers
{
    private ASN1ObjectIdentifier contentType;
    private ASN1Encodable        content;

    /**
     * Return an ContentInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link cms.ContentInfo} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with ContentInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static cms.ContentInfo getInstance(
        Object  obj)
    {
        if (obj instanceof cms.ContentInfo)
        {
            return (cms.ContentInfo)obj;
        }
        else if (obj != null)
        {
            return new cms.ContentInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static cms.ContentInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private ContentInfo(
        ASN1Sequence  seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);

        if (seq.size() > 1)
        {
            ASN1TaggedObject tagged = (ASN1TaggedObject)seq.getObjectAt(1);
            if (!tagged.isExplicit() || tagged.getTagNo() != 0)
            {
                throw new IllegalArgumentException("Bad tag for 'content'");
            }

            content = tagged.getObject();
        }
    }

    public ContentInfo(
        ASN1ObjectIdentifier contentType,
        ASN1Encodable        content)
    {
        this.contentType = contentType;
        this.content = content;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector(2);

        v.add(contentType);

        if (content != null)
        {
            v.add(new BERTaggedObject(0, content));
        }

        return new BERSequence(v);
    }
}