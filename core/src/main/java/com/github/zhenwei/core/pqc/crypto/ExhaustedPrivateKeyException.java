package com.github.zhenwei.core.pqc.crypto;

public class ExhaustedPrivateKeyException
    extends IllegalStateException
{
    public ExhaustedPrivateKeyException(String msg)
    {
        super(msg);
    }
}