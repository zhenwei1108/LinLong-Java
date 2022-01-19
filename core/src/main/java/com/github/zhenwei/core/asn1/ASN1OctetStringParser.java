package com.github.zhenwei.core.asn1;

import java.io.InputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.InMemoryRepresentable;

/**
 * A basic parser for an OCTET STRING object
 */
public interface ASN1OctetStringParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Return the content of the OCTET STRING as an InputStream.
     *
     * @return an InputStream representing the OCTET STRING's content.
     */
    public InputStream getOctetStream();
}