package com.github.zhenwei.pkix.cms;

import org.bouncycastle.cms.CMSException;

public class CMSVerifierCertificateNotValidException
    extends CMSException
{
    public CMSVerifierCertificateNotValidException(
        String msg)
    {
        super(msg);
    }
}