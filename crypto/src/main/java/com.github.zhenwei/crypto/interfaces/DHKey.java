package com.github.zhenwei.crypto.interfaces;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/**
 * The interface to a Diffie-Hellman key.
 *
 * @see DHParameterSpec
 * @see DHPublicKey
 * @see DHPrivateKey
 */
public abstract interface DHKey
{
    /**
     * Returns the key parameters.
     *
     * @return the key parameters
     */
    public DHParameterSpec getParams();
}