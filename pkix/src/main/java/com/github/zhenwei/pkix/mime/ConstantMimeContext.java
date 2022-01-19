package com.github.zhenwei.pkix.mime;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeContext;
import org.bouncycastle.mime.MimeMultipartContext;

public class ConstantMimeContext
    implements MimeContext, MimeMultipartContext
{
    public InputStream applyContext(Headers headers, InputStream contentStream)
        throws IOException
    {
        return contentStream;
    }

    public MimeContext createContext(int partNo)
        throws IOException
    {
        return this;
    }
}