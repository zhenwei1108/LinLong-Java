package com.github.zhenwei.crypto.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;

/**
 * The interface to a Diffie-Hellman public key.
 *
 * @see javax.crypto.interfaces.DHKey
 * @see DHPrivateKey
 */
public abstract interface DHPublicKey
    extends DHKey, PublicKey
{
    /**
     * Returns the public value, <code>y</code>.
     *
     * @return the public value, <code>y</code>
     */
    public BigInteger getY();
}