package com.github.zhenwei.core.math.ec;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPointMap;

public class ScaleXPointMap implements ECPointMap
{
    protected final ECFieldElement scale;

    public ScaleXPointMap(ECFieldElement scale)
    {
        this.scale = scale;
    }

    public ECPoint map(ECPoint p)
    {
        return p.scaleX(scale);
    }
}