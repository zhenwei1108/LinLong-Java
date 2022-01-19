package com.github.zhenwei.core.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Interface implemented by objects that can be converted from streaming to in-memory objects.
 */
public interface InMemoryRepresentable
{
    /**
     * Get the in-memory representation of the ASN.1 object.
     * @return an ASN1Primitive representing the loaded object.
     * @throws IOException for bad input data.
     */
    ASN1Primitive getLoadedObject()
        throws IOException;
}