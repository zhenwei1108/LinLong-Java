package com.github.zhenwei.core.math.ec.endo;

import java.math.BigInteger;
import org.bouncycastle.math.ec.endo.ScalarSplitParameters;

public class GLVTypeAParameters
{
    protected final BigInteger i, lambda;
    protected final ScalarSplitParameters splitParams;

    public GLVTypeAParameters(BigInteger i, BigInteger lambda, ScalarSplitParameters splitParams)
    {
        this.i = i;
        this.lambda = lambda;
        this.splitParams = splitParams;
    }

    public BigInteger getI()
    {
        return i;
    }

    public BigInteger getLambda()
    {
        return lambda;
    }

    public ScalarSplitParameters getSplitParams()
    {
        return splitParams;
    }
}