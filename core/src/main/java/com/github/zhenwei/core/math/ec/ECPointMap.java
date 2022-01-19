package com.github.zhenwei.core.math.ec;

import org.bouncycastle.math.ec.ECPoint;

public interface ECPointMap
{
    ECPoint map(ECPoint p);
}