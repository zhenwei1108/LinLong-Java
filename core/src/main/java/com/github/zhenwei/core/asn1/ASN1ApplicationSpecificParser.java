package com.github.zhenwei.core.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERTags;

/**
 * Interface to parse ASN.1 ApplicationSpecific objects.
 * 
 * @deprecated Test for {@link ASN1TaggedObjectParser} with
 *             {@link ASN1TaggedObjectParser#getTagClass() tag class} of
 *             {@link BERTags#APPLICATION} instead.
 */
public interface ASN1ApplicationSpecificParser
    extends ASN1TaggedObjectParser
{
    /**
     * Read the next object in the parser.
     *
     * @return an ASN1Encodable
     * @throws IOException on a parsing or decoding error.
     */
    ASN1Encodable readObject()
        throws IOException;
}