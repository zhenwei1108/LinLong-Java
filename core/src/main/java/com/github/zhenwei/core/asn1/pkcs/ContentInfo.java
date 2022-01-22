package com.github.zhenwei.core.asn1.pkcs;









import BERTaggedObject;
import DLSequence;
import java.util.Enumeration;

public class ContentInfo
    extends ASN1Object
    implements PKCSObjectIdentifiers
{
    private ASN1ObjectIdentifier contentType;
    private ASN1Encodable content;
    private boolean       isBer = true;

    public static pkcs.ContentInfo getInstance(
        Object  obj)
    {
        if (obj instanceof pkcs.ContentInfo)
        {
            return (pkcs.ContentInfo)obj;
        }

        if (obj != null)
        {
            return new pkcs.ContentInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private ContentInfo(
        ASN1Sequence  seq)
    {
        Enumeration   e = seq.getObjects();

        contentType = (ASN1ObjectIdentifier)e.nextElement();

        if (e.hasMoreElements())
        {
            content = ((ASN1TaggedObject)e.nextElement()).getObject();
        }

        isBer = seq instanceof BERSequence;
    }

    public ContentInfo(
        ASN1ObjectIdentifier contentType,
        ASN1Encodable content)
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
     * <pre>
     * ContentInfo ::= SEQUENCE {
     *          contentType ContentType,
     *          content
     *          [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(contentType);

        if (content != null)
        {
            v.add(new BERTaggedObject(true, 0, content));
        }

        if (isBer)
        {
            return new BERSequence(v);
        }
        else
        {
            return new DLSequence(v);
        }
    }
}