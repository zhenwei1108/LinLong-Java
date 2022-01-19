package com.github.zhenwei.pkix.mime;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.mime.Headers;

public interface MimeContext
{
    InputStream applyContext(Headers headers, InputStream contentStream)
        throws IOException;
}