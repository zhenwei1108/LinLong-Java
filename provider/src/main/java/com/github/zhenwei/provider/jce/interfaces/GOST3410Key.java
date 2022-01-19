package com.github.zhenwei.provider.jce.interfaces;

import org.bouncycastle.jce.interfaces.GOST3410Params;

/**
 * Main interface for a GOST 3410-94 key.
 */
public interface GOST3410Key
{

    public GOST3410Params getParameters();

}