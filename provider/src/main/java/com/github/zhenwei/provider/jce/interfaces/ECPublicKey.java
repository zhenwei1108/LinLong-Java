package com.github.zhenwei.provider.jce.interfaces;

 
import java.security.PublicKey;

/**
 * interface for elliptic curve public keys.
 */
public interface ECPublicKey
    extends ECKey, PublicKey
{
    /**
     * return the public point Q
     */
    public ECPoint getQ();
}