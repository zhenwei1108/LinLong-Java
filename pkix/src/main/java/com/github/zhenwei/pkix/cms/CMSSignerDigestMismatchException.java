package com.github.zhenwei.pkix.cms;

import org.bouncycastle.cms.CMSException;

public class CMSSignerDigestMismatchException
    extends CMSException
{
    public CMSSignerDigestMismatchException(
        String msg)
    {
        super(msg);
    }
}