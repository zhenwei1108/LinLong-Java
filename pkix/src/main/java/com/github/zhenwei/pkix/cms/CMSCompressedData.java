package com.github.zhenwei.pkix.cms;


import cms.CompressedData;
 
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.util.Encodable;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.operator.InputExpander;
import org.bouncycastle.operator.InputExpanderProvider;


/**
 * containing class for an CMS Compressed Data object
 * <pre>
 *     CMSCompressedData cd = new CMSCompressedData(inputStream);
 *
 *     process(cd.getContent(new ZlibExpanderProvider()));
 * </pre>
 */
public class CMSCompressedData
    implements Encodable
{
    ContentInfo                 contentInfo;
    CompressedData              comData;

    public CMSCompressedData(
        byte[]    compressedData) 
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSCompressedData(
        InputStream    compressedData) 
        throws CMSException
    {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSCompressedData(
        ContentInfo contentInfo)
        throws CMSException
    {
        this.contentInfo = contentInfo;

        try
        {
            this.comData = CompressedData.getInstance(contentInfo.getContent());
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentInfo.getContentType();
    }

    public ASN1ObjectIdentifier getCompressedContentType()
    {
        return comData.getEncapContentInfo().getContentType();
    }

    public CMSTypedStream getContentStream(InputExpanderProvider expanderProvider)
    {
        ContentInfo     content = comData.getEncapContentInfo();

        ASN1OctetString bytes = (ASN1OctetString)content.getContent();
        InputExpander   expander = expanderProvider.get(comData.getCompressionAlgorithmIdentifier());
        InputStream     zIn = expander.getInputStream(bytes.getOctetStream());

        return new CMSTypedStream(content.getContentType(), zIn);
    }

    /**
     * Return the uncompressed content.
     *
     * @param expanderProvider a provider of expander algorithm implementations.
     * @return the uncompressed content
     * @throws CMSException if there is an exception un-compressing the data.
     */
    public byte[] getContent(InputExpanderProvider expanderProvider)
        throws CMSException
    {
        ContentInfo     content = comData.getEncapContentInfo();

        ASN1OctetString bytes = (ASN1OctetString)content.getContent();
        InputExpander   expander = expanderProvider.get(comData.getCompressionAlgorithmIdentifier());
        InputStream     zIn = expander.getInputStream(bytes.getOctetStream());

        try
        {
            return CMSUtils.streamToByteArray(zIn);
        }
        catch (IOException e)
        {
            throw new CMSException("exception reading compressed stream.", e);
        }
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure()
    {
        return contentInfo;
    }
    
    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }
}