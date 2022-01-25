package com.github.zhenwei.pkix.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import com.github.zhenwei.core.asn1.ASN1OctetStringParser;
import com.github.zhenwei.core.asn1.ASN1SequenceParser;
import com.github.zhenwei.core.asn1.BERTags;
import com.github.zhenwei.pkix.util.asn1.cms.CompressedDataParser;
import com.github.zhenwei.pkix.util.asn1.cms.ContentInfoParser;
import  com.github.zhenwei.pkix.operator.InputExpander;
import  com.github.zhenwei.pkix.operator.InputExpanderProvider;

/**
 * Class for reading a CMS Compressed Data stream.
 * <pre>
 *     CMSCompressedDataParser cp = new CMSCompressedDataParser(inputStream);
 *      
 *     process(cp.getContent(new ZlibExpanderProvider()).getContentStream());
 * </pre>
 *  Note: this class does not introduce buffering - if you are processing large files you should create
 *  the parser with:
 *  <pre>
 *      CMSCompressedDataParser     ep = new CMSCompressedDataParser(new BufferedInputStream(inputStream, bufSize));
 *  </pre>
 *  where bufSize is a suitably large buffer size.
 */
public class CMSCompressedDataParser
    extends CMSContentInfoParser
{
    public CMSCompressedDataParser(
        byte[]    compressedData) 
        throws CMSException
    {
        this(new ByteArrayInputStream(compressedData));
    }

    public CMSCompressedDataParser(
        InputStream    compressedData) 
        throws CMSException
    {
        super(compressedData);
    }

    /**
     * Return a typed stream which will allow the reading of the compressed content in
     * expanded form.
     *
     * @param expanderProvider a provider of expander algorithm implementations.
     * @return a type stream which will yield the un-compressed content.
     * @throws CMSException if there is an exception parsing the CompressedData object.
     */
    public CMSTypedStream  getContent(InputExpanderProvider expanderProvider)
        throws CMSException
    {
        try
        {
            CompressedDataParser  comData = new CompressedDataParser((ASN1SequenceParser)_contentInfo.getContent(BERTags.SEQUENCE));
            ContentInfoParser     content = comData.getEncapContentInfo();
            InputExpander expander = expanderProvider.get(comData.getCompressionAlgorithmIdentifier());

            ASN1OctetStringParser bytes = (ASN1OctetStringParser)content.getContent(BERTags.OCTET_STRING);

            return new CMSTypedStream(content.getContentType(), expander.getInputStream(bytes.getOctetStream()));
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading compressed content.", e);
        }
    }
}