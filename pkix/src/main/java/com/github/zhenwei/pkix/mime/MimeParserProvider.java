package com.github.zhenwei.pkix.mime;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeParser;

public interface MimeParserProvider
{
    MimeParser createParser(InputStream source)
        throws IOException;

    MimeParser createParser(Headers headers, InputStream source)
        throws IOException;
}