package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.PrivateKey;

public interface XDHPrivateKey
    extends XDHKey, PrivateKey
{
    /**
     * Return the public key associated with this private key.
     *
     * @return an XDHPublicKey
     */
    XDHPublicKey getPublicKey();
}