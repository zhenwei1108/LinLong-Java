package com.github.zhenwei.core.crypto.modes.kgcm;

import org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier;
import org.bouncycastle.crypto.modes.kgcm.KGCMUtil_128;

public class BasicKGCMMultiplier_128
    implements KGCMMultiplier
{
    private final long[] H = new long[KGCMUtil_128.SIZE];

    public void init(long[] H)
    {
        KGCMUtil_128.copy(H,  this.H);
    }

    public void multiplyH(long[] z)
    {
        KGCMUtil_128.multiply(z, H, z);
    }
}