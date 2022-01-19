package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.PrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;

public interface EdDSAPrivateKey
    extends EdDSAKey, PrivateKey
{
    /**
     * Return the public key associated with this private key.
     *
     * @return an EdDSAPublicKey
     */
    EdDSAPublicKey getPublicKey();
}