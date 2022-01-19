package com.github.zhenwei.core.asn1;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Stream that outputs encoding based on distinguished encoding rules.
 */
class DEROutputStream
    extends DLOutputStream
{
    DEROutputStream(OutputStream os)
    {
        super(os);
    }

    org.bouncycastle.asn1.DEROutputStream getDERSubStream()
    {
        return this;
    }

    void writeElements(ASN1Encodable[] elements)
        throws IOException
    {
        int count = elements.length;
        for (int i = 0; i < count; ++i)
        {
            elements[i].toASN1Primitive().toDERObject().encode(this, true);
        }
    }

    void writePrimitive(ASN1Primitive primitive, boolean withTag) throws IOException
    {
        primitive.toDERObject().encode(this, withTag);
    }

    void writePrimitives(ASN1Primitive[] primitives)
        throws IOException
    {
        int count = primitives.length;
        for (int i = 0; i < count; ++i)
        {
            primitives[i].toDERObject().encode(this, true);
        }
    }
}