package com.github.zhenwei.core.math.field;

import java.math.BigInteger;

public interface FiniteField
{
    BigInteger getCharacteristic();

    int getDimension();
}