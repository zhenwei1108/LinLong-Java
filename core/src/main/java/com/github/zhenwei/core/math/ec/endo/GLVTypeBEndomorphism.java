package com.github.zhenwei.core.math.ec.endo;


import ECPointMap;
import ScaleXPointMap;
import com.github.zhenwei.core.math.ec.ECCurve;
import java.math.BigInteger;

public class GLVTypeBEndomorphism implements GLVEndomorphism
{
    protected final GLVTypeBParameters parameters;
    protected final ECPointMap pointMap;

    public GLVTypeBEndomorphism(ECCurve curve, GLVTypeBParameters parameters)
    {
        /*
         * NOTE: 'curve' MUST only be used to create a suitable ECFieldElement. Due to the way
         * ECCurve configuration works, 'curve' will not be the actual instance of ECCurve that the
         * endomorphism is being used with.
         */

        this.parameters = parameters;
        this.pointMap = new ScaleXPointMap(curve.fromBigInteger(parameters.getBeta()));
    }

    public BigInteger[] decomposeScalar(BigInteger k)
    {
        return EndoUtil.decomposeScalar(parameters.getSplitParams(), k);
    }

    public ECPointMap getPointMap()
    {
        return pointMap;
    }

    public boolean hasEfficientPointMap()
    {
        return true;
    }
}