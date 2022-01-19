package com.github.zhenwei.core.crypto.modes.gcm;

import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;

public class BasicGCMMultiplier
    implements GCMMultiplier
{
    private long[] H;

    public void init(byte[] H)
    {
        this.H = GCMUtil.asLongs(H);
    }

    public void multiplyH(byte[] x)
    {
        long[] t = GCMUtil.asLongs(x);
        GCMUtil.multiply(t, H);
        GCMUtil.asBytes(t, x);
    }
}