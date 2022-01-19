package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.DataLengthException;

public class OutputLengthException
    extends DataLengthException
{
    public OutputLengthException(String msg)
    {
        super(msg);
    }
}