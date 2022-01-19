package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Mac;

/**
 * base interface for general purpose Mac based byte derivation functions.
 */
public interface MacDerivationFunction
    extends DerivationFunction
{
    /**
     * return the MAC used as the basis for the function
     *
     * @return the Mac.
     */
    public Mac getMac();
}