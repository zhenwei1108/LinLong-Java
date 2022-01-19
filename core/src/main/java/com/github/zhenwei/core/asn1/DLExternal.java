package com.github.zhenwei.core.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;

/**
 * Class representing the Definite-Length-type External
 */
public class DLExternal
    extends ASN1External
{
    /**
     * Construct a Definite-Length EXTERNAL object, the input encoding vector must have exactly two elements on it.
     * <p>
     * Acceptable input formats are:
     * <ul>
     * <li> {@link ASN1ObjectIdentifier} + data {@link DERTaggedObject} (direct reference form)</li>
     * <li> {@link ASN1Integer} + data {@link DERTaggedObject} (indirect reference form)</li>
     * <li> Anything but {@link DERTaggedObject} + data {@link DERTaggedObject} (data value form)</li>
     * </ul>
     *
     * @throws IllegalArgumentException if input size is wrong, or input is not an acceptable format
     *
     * @deprecated Use {@link org.bouncycastle.asn1.DLExternal#DLExternal(DLSequence)} instead.
     */
    public DLExternal(ASN1EncodableVector vector)
    {
        this(DLFactory.createSequence(vector));
    }

    /**
     * Construct a Definite-Length EXTERNAL object, the input sequence must have exactly two elements on it.
     * <p>
     * Acceptable input formats are:
     * <ul>
     * <li> {@link ASN1ObjectIdentifier} + data {@link DERTaggedObject} (direct reference form)</li>
     * <li> {@link ASN1Integer} + data {@link DERTaggedObject} (indirect reference form)</li>
     * <li> Anything but {@link DERTaggedObject} + data {@link DERTaggedObject} (data value form)</li>
     * </ul>
     *
     * @throws IllegalArgumentException if input size is wrong, or input is not an acceptable format
     */
    public DLExternal(DLSequence sequence)
    {
        super(sequence);
    }

    /**
     * Creates a new instance of DERExternal
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param externalData The external data in its encoded form.
     */
    public DLExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference,
        ASN1Primitive dataValueDescriptor, DERTaggedObject externalData)
    {
        this(directReference, indirectReference, dataValueDescriptor, externalData.getTagNo(),
            externalData.toASN1Primitive());
    }

    /**
     * Creates a new instance of Definite-Length External.
     * See X.690 for more informations about the meaning of these parameters
     * @param directReference The direct reference or <code>null</code> if not set.
     * @param indirectReference The indirect reference or <code>null</code> if not set.
     * @param dataValueDescriptor The data value descriptor or <code>null</code> if not set.
     * @param encoding The encoding to be used for the external data
     * @param externalData The external data
     */
    public DLExternal(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference,
        ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData)
    {
        super(directReference, indirectReference, dataValueDescriptor, encoding, externalData);
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }

    int encodedLength(boolean withTag) throws IOException
    {
        int contentsLength = 0;
        if (directReference != null)
        {
            contentsLength += directReference.encodedLength(true);
        }
        if (indirectReference != null)
        {
            contentsLength += indirectReference.encodedLength(true);
        }
        if (dataValueDescriptor != null)
        {
            contentsLength += dataValueDescriptor.toDLObject().encodedLength(true);
        }

        contentsLength += new DLTaggedObject(true, encoding, externalContent).encodedLength(true);

        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contentsLength);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = ASN1OutputStream.create(bOut, ASN1Encoding.DL);

        if (directReference != null)
        {
            aOut.writePrimitive(directReference, true);
        }
        if (indirectReference != null)
        {
            aOut.writePrimitive(indirectReference, true);
        }
        if (dataValueDescriptor != null)
        {
            aOut.writePrimitive(dataValueDescriptor, true);
        }

        aOut.writePrimitive(new DLTaggedObject(true, encoding, externalContent), true);

        aOut.flushInternal();

        out.writeEncodingDL(withTag, BERTags.CONSTRUCTED | BERTags.EXTERNAL, bOut.toByteArray());
    }
}