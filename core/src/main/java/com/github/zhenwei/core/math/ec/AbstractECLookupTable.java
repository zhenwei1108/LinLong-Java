package com.github.zhenwei.core.math.ec;

import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;

public abstract class AbstractECLookupTable
    implements ECLookupTable
{
    public ECPoint lookupVar(int index)
    {
        return lookup(index);
    }
}