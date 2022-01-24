package com.github.zhenwei.pkix.util.asn1.cms;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.BERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;

/** 
 * <a href="https://tools.ietf.org/html/rfc3274">RFC 3274</a>: CMS Compressed Data.
 * 
 * <pre>
 * CompressedData ::= SEQUENCE {
 *     version CMSVersion,
 *     compressionAlgorithm CompressionAlgorithmIdentifier,
 *     encapContentInfo EncapsulatedContentInfo
 * }
 * </pre>
 */
public class CompressedData
    extends ASN1Object
{
    private ASN1Integer           version;
    private AlgorithmIdentifier  compressionAlgorithm;
    private ContentInfo          encapContentInfo;

    public CompressedData(
        AlgorithmIdentifier compressionAlgorithm,
        ContentInfo         encapContentInfo)
    {
        this.version = new ASN1Integer(0);
        this.compressionAlgorithm = compressionAlgorithm;
        this.encapContentInfo = encapContentInfo;
    }
    
    private CompressedData(
        ASN1Sequence seq)
    {
        this.version = (ASN1Integer)seq.getObjectAt(0);
        this.compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));
    }

    /**
     * Return a CompressedData object from a tagged object.
     *
     * @param ato the tagged object holding the object we want.
     * @param isExplicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static CompressedData getInstance(
        ASN1TaggedObject ato,
        boolean isExplicit)
    {
        return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
    }
    
    /**
     * Return a CompressedData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link CompressedData} object
     * <li> {@link com.github.zhenwei.core.asn1.ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with CompressedData structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static CompressedData getInstance(
        Object obj)
    {
        if (obj instanceof CompressedData)
        {
            return (CompressedData)obj;
        }

        if (obj != null)
        {
            return new CompressedData(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier()
    {
        return compressionAlgorithm;
    }

    public ContentInfo getEncapContentInfo()
    {
        return encapContentInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(version);
        v.add(compressionAlgorithm);
        v.add(encapContentInfo);

        return new BERSequence(v);
    }
}