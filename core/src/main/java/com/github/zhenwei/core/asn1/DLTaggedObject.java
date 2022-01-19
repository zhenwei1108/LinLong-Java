package com.github.zhenwei.core.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DLSequence;

/**
 * Definite Length TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class DLTaggedObject
    extends ASN1TaggedObject
{
    public DLTaggedObject(int tagNo, ASN1Encodable encodable)
    {
        super(true, tagNo, encodable);
    }

    public DLTaggedObject(int tagClass, int tagNo, ASN1Encodable encodable)
    {
        super(true, tagClass, tagNo, encodable);
    }

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public DLTaggedObject(boolean explicit, int tagNo, ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    public DLTaggedObject(boolean explicit, int tagClass, int tagNo, ASN1Encodable obj)
    {
        super(explicit, tagClass, tagNo, obj);
    }

    DLTaggedObject(int explicitness, int tagClass, int tagNo, ASN1Encodable obj)
    {
        super(explicitness, tagClass, tagNo, obj);
    }

    boolean isConstructed()
    {
        return isExplicit() || obj.toASN1Primitive().toDLObject().isConstructed();
    }

    int encodedLength(boolean withTag) throws IOException
    {
        ASN1Primitive primitive = obj.toASN1Primitive().toDLObject();
        boolean explicit = isExplicit();

        int length = primitive.encodedLength(explicit);

        if (explicit)
        {
            length += ASN1OutputStream.getLengthOfDL(length);
        }

        length += withTag ? ASN1OutputStream.getLengthOfIdentifier(tagNo) : 0;

        return length;
    }

    void encode(ASN1OutputStream out, boolean withTag, int tagClass, int tagNo) throws IOException
    {
//        assert out.getClass().isAssignableFrom(DLOutputStream.class);

        ASN1Primitive primitive = obj.toASN1Primitive().toDLObject();
        boolean explicit = isExplicit();

        if (withTag)
        {
            int flags = tagClass;
            if (explicit || primitive.isConstructed())
            {
                flags |= BERTags.CONSTRUCTED;
            }

            out.writeIdentifier(true, flags, tagNo);
        }

        if (explicit)
        {
            out.writeDL(primitive.encodedLength(true));
        }

        primitive.encode(out.getDLSubStream(), explicit);
    }

    String getASN1Encoding()
    {
        return ASN1Encoding.DL;
    }

    ASN1Sequence rebuildConstructed(ASN1Primitive primitive)
    {
        return new DLSequence(primitive);
    }

    ASN1TaggedObject replaceTag(int tagClass, int tagNo)
    {
        return new org.bouncycastle.asn1.DLTaggedObject(explicitness, tagClass, tagNo, obj);
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }
}