package com.github.zhenwei.crypto.interfaces;

import java.math.BigInteger;
import java.security.PrivateKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPublicKey;

/**
 * The interface to a Diffie-Hellman private key.
 *
 * @see javax.crypto.interfaces.DHKey
 * @see DHPublicKey
 */
public abstract interface DHPrivateKey
    extends DHKey, PrivateKey
{
    /**
     * Returns the private value, <code>x</code>.
     *
     * @return the private value, <code>x</code>
     */
    public BigInteger getX();
}