package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.Key;

public interface SPHINCSKey
    extends Key
{
    byte[] getKeyData();
}