package com.github.zhenwei.core.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1ApplicationSpecificParser;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERTaggedObjectParser;
import org.bouncycastle.asn1.BERTags;

/**
 * A parser for indefinite-length ASN.1 ApplicationSpecific objects.
 * 
 * @deprecated Test for {@link ASN1TaggedObjectParser} with
 *             {@link ASN1TaggedObjectParser#getTagClass() tag class} of
 *             {@link BERTags#APPLICATION} instead.
 */
public class BERApplicationSpecificParser
    extends BERTaggedObjectParser
    implements ASN1ApplicationSpecificParser
{
    BERApplicationSpecificParser(int tagNo, boolean constructed, ASN1StreamParser parser)
    {
        super(BERTags.APPLICATION, tagNo, constructed, parser);
    }

    /**
     * Return the object contained in this application specific object,
     * @return the contained object.
     * @throws IOException if the underlying stream cannot be read, or does not contain an ASN.1 encoding.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        // NOTE: No way to say you're looking for an implicitly-tagged object via ASN1ApplicationSpecificParser
        return parseBaseUniversal(true, -1);
    }
}