package com.github.zhenwei.pkix.operator;

import org.bouncycastle.operator.OperatorException;

public class OperatorCreationException
    extends OperatorException
{
    public OperatorCreationException(String msg, Throwable cause)
    {
        super(msg, cause);
    }

    public OperatorCreationException(String msg)
    {
        super(msg);
    }
}