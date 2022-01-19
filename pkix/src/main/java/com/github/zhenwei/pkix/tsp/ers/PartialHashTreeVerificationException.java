package com.github.zhenwei.pkix.tsp.ers;

import org.bouncycastle.tsp.ers.ERSException;

public class PartialHashTreeVerificationException
    extends ERSException
{
    public PartialHashTreeVerificationException(final String message)
    {
        super(message);
    }
}