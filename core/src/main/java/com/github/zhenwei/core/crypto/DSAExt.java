package com.github.zhenwei.core.crypto;

import java.math.BigInteger;
import org.bouncycastle.crypto.DSA;

/**
 * An "extended" interface for classes implementing DSA-style algorithms, that provides access to
 * the group order.
 */
public interface DSAExt
    extends DSA
{
    /**
     * Get the order of the group that the r, s values in signatures belong to.
     */
    public BigInteger getOrder();
}