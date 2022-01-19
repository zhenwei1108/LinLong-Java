package com.github.zhenwei.core.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;

public abstract class AbstractECMultiplier implements ECMultiplier
{
    public ECPoint multiply(ECPoint p, BigInteger k)
    {
        int sign = k.signum();
        if (sign == 0 || p.isInfinity())
        {
            return p.getCurve().getInfinity();
        }

        ECPoint positive = multiplyPositive(p, k.abs());
        ECPoint result = sign > 0 ? positive : positive.negate();

        /*
         * Although the various multipliers ought not to produce invalid output under normal
         * circumstances, a final check here is advised to guard against fault attacks.
         */
        return checkResult(result);
    }

    protected abstract ECPoint multiplyPositive(ECPoint p, BigInteger k);

    protected ECPoint checkResult(ECPoint p)
    {
        return ECAlgorithms.implCheckResult(p);
    }
}