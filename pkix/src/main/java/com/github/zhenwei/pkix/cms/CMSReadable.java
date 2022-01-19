package com.github.zhenwei.pkix.cms;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.cms.CMSException;

interface CMSReadable
{
    public InputStream getInputStream()
        throws IOException, CMSException;
}