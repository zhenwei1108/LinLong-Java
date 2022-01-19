package com.github.zhenwei.core.crypto.modes.kgcm;

import org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier;
import org.bouncycastle.crypto.modes.kgcm.KGCMUtil_256;

public class BasicKGCMMultiplier_256
    implements KGCMMultiplier
{
    private final long[] H = new long[KGCMUtil_256.SIZE];

    public void init(long[] H)
    {
        KGCMUtil_256.copy(H,  this.H);
    }

    public void multiplyH(long[] z)
    {
        KGCMUtil_256.multiply(z, H, z);
    }
}