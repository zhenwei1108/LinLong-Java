package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.PublicKey;

public interface NHPublicKey
    extends NHKey, PublicKey
{
    byte[] getPublicData();
}