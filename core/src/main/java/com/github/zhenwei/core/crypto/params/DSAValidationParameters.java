package com.github.zhenwei.core.crypto.params;

import org.bouncycastle.util.Arrays;

public class DSAValidationParameters
{
    private int usageIndex;
    private byte[]  seed;
    private int     counter;

    public DSAValidationParameters(
        byte[]  seed,
        int     counter)
    {
        this(seed, counter, -1);
    }

    public DSAValidationParameters(
        byte[]  seed,
        int     counter,
        int     usageIndex)
    {
        this.seed = Arrays.clone(seed);
        this.counter = counter;
        this.usageIndex = usageIndex;
    }

    public int getCounter()
    {
        return counter;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    public int getUsageIndex()
    {
        return usageIndex;
    }

    public int hashCode()
    {
        return counter ^ Arrays.hashCode(seed);
    }
    
    public boolean equals(
        Object o)
    {
        if (!(o instanceof org.bouncycastle.crypto.params.DSAValidationParameters))
        {
            return false;
        }

        org.bouncycastle.crypto.params.DSAValidationParameters other = (org.bouncycastle.crypto.params.DSAValidationParameters)o;

        if (other.counter != this.counter)
        {
            return false;
        }

        return Arrays.areEqual(this.seed, other.seed);
    }
}