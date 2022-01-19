package com.github.zhenwei.core.pqc.crypto.xmss;

import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * WOTS+ signature.
 */
final class WOTSPlusSignature
{

    private byte[][] signature;

    protected WOTSPlusSignature(WOTSPlusParameters params, byte[][] signature)
    {
        super();
        if (params == null)
        {
            throw new NullPointerException("params == null");
        }
        if (signature == null)
        {
            throw new NullPointerException("signature == null");
        }
        if (XMSSUtil.hasNullPointer(signature))
        {
            throw new NullPointerException("signature byte array == null");
        }
        if (signature.length != params.getLen())
        {
            throw new IllegalArgumentException("wrong signature size");
        }
        for (int i = 0; i < signature.length; i++)
        {
            if (signature[i].length != params.getTreeDigestSize())
            {
                throw new IllegalArgumentException("wrong signature format");
            }
        }
        this.signature = XMSSUtil.cloneArray(signature);
    }

    public byte[][] toByteArray()
    {
        return XMSSUtil.cloneArray(signature);
    }
}