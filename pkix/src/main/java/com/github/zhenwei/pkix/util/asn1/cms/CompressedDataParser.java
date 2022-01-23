package com.github.zhenwei.pkix.util.asn1.cms;


import ASN1SequenceParser;
import com.github.zhenwei.core.asn1.ASN1Integer;

import java.io.IOException;

/**
 * Parser of <a href="https://tools.ietf.org/html/rfc3274">RFC 3274</a> {@link CompressedData} object.
 * <p>
 * <pre>
 * CompressedData ::= SEQUENCE {
 *     version CMSVersion,
 *     compressionAlgorithm CompressionAlgorithmIdentifier,
 *     encapContentInfo EncapsulatedContentInfo
 * }
 * </pre>
 */
public class CompressedDataParser
{
    private ASN1Integer _version;
    private AlgorithmIdentifier _compressionAlgorithm;
    private ContentInfoParser _encapContentInfo;

    public CompressedDataParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        this._version = (ASN1Integer)seq.readObject();
        this._compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.readObject().toASN1Primitive());
        this._encapContentInfo = new ContentInfoParser((ASN1SequenceParser)seq.readObject());
    }

    public ASN1Integer getVersion()
    {
        return _version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier()
    {
        return _compressionAlgorithm;
    }

    public ContentInfoParser getEncapContentInfo()
    {
        return _encapContentInfo;
    }
}