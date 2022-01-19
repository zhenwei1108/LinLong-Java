package com.github.zhenwei.pkix.openssl;

import org.bouncycastle.openssl.PEMException;

public class PasswordException
    extends PEMException
{
    public PasswordException(String msg)
    {
        super(msg);
    }
}