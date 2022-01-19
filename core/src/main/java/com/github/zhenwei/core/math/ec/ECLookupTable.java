package com.github.zhenwei.core.math.ec;

import org.bouncycastle.math.ec.ECPoint;

public interface ECLookupTable
{
    int getSize();
    ECPoint lookup(int index);
    ECPoint lookupVar(int index);
}