package com.github.zhenwei.core.math.ec.endo;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.PreCompInfo;
import org.bouncycastle.math.ec.endo.ECEndomorphism;

public class EndoPreCompInfo implements PreCompInfo
{
    protected ECEndomorphism endomorphism;

    protected ECPoint mappedPoint;

    public ECEndomorphism getEndomorphism()
    {
        return endomorphism;
    }

    public void setEndomorphism(ECEndomorphism endomorphism)
    {
        this.endomorphism = endomorphism;
    }

    public ECPoint getMappedPoint()
    {
        return mappedPoint;
    }

    public void setMappedPoint(ECPoint mappedPoint)
    {
        this.mappedPoint = mappedPoint;
    }
}