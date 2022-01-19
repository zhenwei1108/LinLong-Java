package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.PrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;

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