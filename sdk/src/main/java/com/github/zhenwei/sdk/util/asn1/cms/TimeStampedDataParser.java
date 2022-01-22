package com.github.zhenwei.sdk.util.asn1.cms;




import ASN1OctetStringParser;

import ASN1SequenceParser;

import java.io.IOException;

/**
 * Parser for <a href="https://tools.ietf.org/html/rfc5544">RFC 5544</a>:
 * {@link TimeStampedData} object.
 * <p>
 * <pre>
 * TimeStampedData ::= SEQUENCE {
 *   version              INTEGER { v1(1) },
 *   dataUri              IA5String OPTIONAL,
 *   metaData             MetaData OPTIONAL,
 *   content              OCTET STRING OPTIONAL,
 *   temporalEvidence     Evidence
 * }
 * </pre>
 */
public class TimeStampedDataParser
{
    private ASN1Integer version;
    private ASN1IA5String dataUri;
    private MetaData metaData;
    private ASN1OctetStringParser content;
    private Evidence temporalEvidence;
    private ASN1SequenceParser parser;

    private TimeStampedDataParser(ASN1SequenceParser parser)
        throws IOException
    {
        this.parser = parser;
        this.version = ASN1Integer.getInstance(parser.readObject());

        ASN1Encodable obj = parser.readObject();

        if (obj instanceof ASN1IA5String)
        {
            this.dataUri = ASN1IA5String.getInstance(obj);
            obj = parser.readObject();
        }
        if (obj instanceof MetaData || obj instanceof ASN1SequenceParser)
        {
            this.metaData = MetaData.getInstance(obj.toASN1Primitive());
            obj = parser.readObject();
        }
        if (obj instanceof ASN1OctetStringParser)
        {
            this.content = (ASN1OctetStringParser)obj;
        }
    }

    public static cms.TimeStampedDataParser getInstance(Object obj)
        throws IOException
    {
        if (obj instanceof ASN1Sequence)
        {
            return new cms.TimeStampedDataParser(((ASN1Sequence)obj).parser());
        }
        if (obj instanceof ASN1SequenceParser)
        {
            return new cms.TimeStampedDataParser((ASN1SequenceParser)obj);
        }

        return null;
    }

    public int getVersion()
    {
        return version.getValue().intValue();
    }

    /**
     * @deprecated Use {@link #getDataUriIA5()} instead.
     */
    public DERIA5String getDataUri()
    {
        return null == dataUri || dataUri instanceof DERIA5String
            ?   (DERIA5String)dataUri
            :   new DERIA5String(dataUri.getString(), false);
    }

    public ASN1IA5String getDataUriIA5()
    {
        return dataUri;
    }

    public MetaData getMetaData()
    {
        return metaData;
    }

    public ASN1OctetStringParser getContent()
    {
        return content;
    }

    public Evidence getTemporalEvidence()
        throws IOException
    {
        if (temporalEvidence == null)
        {
            temporalEvidence = Evidence.getInstance(parser.readObject().toASN1Primitive());
        }

        return temporalEvidence;
    }
}