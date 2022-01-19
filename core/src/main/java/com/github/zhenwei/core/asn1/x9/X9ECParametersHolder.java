package com.github.zhenwei.core.asn1.x9;

import org.bouncycastle.asn1.x9.X9ECParameters;

/**
 * A holding class that allows for X9ECParameters to be lazily constructed.
 */
public abstract class X9ECParametersHolder
{
    private X9ECParameters params;

    public synchronized X9ECParameters getParameters()
    {
        if (params == null)
        {
            params = createParameters();
        }

        return params;
    }

    protected abstract X9ECParameters createParameters();
}