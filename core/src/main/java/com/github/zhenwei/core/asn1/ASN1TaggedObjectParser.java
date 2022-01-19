package com.github.zhenwei.core.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.InMemoryRepresentable;

/**
 * Interface for the parsing of a generic tagged ASN.1 object.
 */
public interface ASN1TaggedObjectParser
    extends ASN1Encodable, InMemoryRepresentable
{
    /**
     * Return the tag class associated with this object.
     *
     * @return the tag class.
     */
    int getTagClass();

    /**
     * Return the tag number associated with this object.
     *
     * @return the tag number.
     */
    int getTagNo();

    boolean hasContextTag(int tagNo);

    boolean hasTag(int tagClass, int tagNo);

    /**
     *
     * Return a parser for the actual object tagged.
     *
     * @param tag        the primitive tag value for the object tagged originally.
     * @param isExplicit true if the tagging was done explicitly.
     * @return a parser for the tagged object.
     * @throws IOException if a parser cannot be constructed.
     *
     * @deprecated This parser now includes the {@link #getTagClass() tag class}.
     *             This method will raise an exception if it is not
     *             {@link BERTags#CONTEXT_SPECIFIC}. Use
     *             {@link ASN1Util#parseContextBaseUniversal(org.bouncycastle.asn1.ASN1TaggedObjectParser, int, int, boolean, int)}
     *             as a direct replacement, or use
     *             {@link #parseBaseUniversal(boolean, int)} only after confirming
     *             the expected tag class (e.g.
     *             {@link ASN1Util#tryParseContextBaseUniversal(org.bouncycastle.asn1.ASN1TaggedObjectParser, int, boolean, int)}.
     */
    ASN1Encodable getObjectParser(int tag, boolean isExplicit)
        throws IOException;

//    ASN1Encodable parseBaseObject(boolean declaredExplicit, int baseTagClass, int baseTagNo,
//        boolean baseDeclaredExplicit) throws IOException;

    ASN1Encodable parseBaseUniversal(boolean declaredExplicit, int baseTagNo) throws IOException;
}