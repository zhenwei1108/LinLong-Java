package com.github.zhenwei.core.math.field;

import java.math.BigInteger;
import org.bouncycastle.math.field.FiniteField;

class PrimeField implements FiniteField
{
    protected final BigInteger characteristic;

    PrimeField(BigInteger characteristic)
    {
        this.characteristic = characteristic;
    }

    public BigInteger getCharacteristic()
    {
        return characteristic;
    }

    public int getDimension()
    {
        return 1;
    }

    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof org.bouncycastle.math.field.PrimeField))
        {
            return false;
        }
        org.bouncycastle.math.field.PrimeField other = (org.bouncycastle.math.field.PrimeField)obj;
        return characteristic.equals(other.characteristic);
    }

    public int hashCode()
    {
        return characteristic.hashCode();
    }
}