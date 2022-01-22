package com.github.zhenwei.core.math.ec;

public interface ECLookupTable
{
    int getSize();
    ECPoint lookup(int index);
    ECPoint lookupVar(int index);
}