package com.github.zhenwei.pkix.tsp.ers;

import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.tsp.ers.ERSCachingData;

/**
 * Generic class for holding byte[] data for RFC 4998 ERS.
 */
public class ERSByteData
    extends ERSCachingData
{
    private final byte[] content;

    public ERSByteData(byte[] content)
    {
        this.content = content;
    }

    protected byte[] calculateHash(DigestCalculator digestCalculator)
    {
        return ERSUtil.calculateDigest(digestCalculator, content);
    }
}