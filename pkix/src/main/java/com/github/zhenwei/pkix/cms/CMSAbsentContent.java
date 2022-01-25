package com.github.zhenwei.pkix.cms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.pkix.util.asn1.cms.CMSObjectIdentifiers;

/**
 * a class representing null or absent content.
 */
public class CMSAbsentContent
    implements CMSTypedData, CMSReadable
{
    private final ASN1ObjectIdentifier type;

    public CMSAbsentContent()
    {
        this(CMSObjectIdentifiers.data);
    }

    public CMSAbsentContent(
        ASN1ObjectIdentifier type)
    {
        this.type = type;
    }

    public InputStream getInputStream()
    {
        return null;
    }

    public void write(OutputStream zOut)
        throws IOException, CMSException
    {
        // do nothing
    }

    public Object getContent()
    {
        return null;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return type;
    }
}