package com.github.zhenwei.core.crypto.params;


import com.github.zhenwei.core.util.Arrays;

public class DHValidationParameters
{
    private byte[]  seed;
    private int     counter;

    public DHValidationParameters(
        byte[]  seed,
        int     counter)
    {
        this.seed = Arrays.clone(seed);
        this.counter = counter;
    }

    public int getCounter()
    {
        return counter;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof org.bouncycastle.crypto.params.DHValidationParameters))
        {
            return false;
        }

        org.bouncycastle.crypto.params.DHValidationParameters other = (org.bouncycastle.crypto.params.DHValidationParameters)o;

        if (other.counter != this.counter)
        {
            return false;
        }

        return Arrays.areEqual(this.seed, other.seed);
    }

    public int hashCode()
    {
        return counter ^ Arrays.hashCode(seed);
    }
}