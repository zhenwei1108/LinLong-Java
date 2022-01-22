package com.github.zhenwei.sdk.util.asn1.cms;


import ASN1SequenceParser;
import ASN1TaggedObjectParser;
import ASN1Util;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import java.io.IOException;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> {@link ContentInfo} object parser.
 *
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 * </pre>
 */
public class ContentInfoParser
{
    private ASN1ObjectIdentifier contentType;
    private ASN1TaggedObjectParser content;

    public ContentInfoParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        contentType = (ASN1ObjectIdentifier)seq.readObject();
        content = (ASN1TaggedObjectParser)seq.readObject();
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public ASN1Encodable getContent(
        int  tag)
        throws IOException
    {
        if (content != null)
        {
            return ASN1Util.parseContextBaseUniversal(content, 0, true, tag);
        }

        return null;
    }
}