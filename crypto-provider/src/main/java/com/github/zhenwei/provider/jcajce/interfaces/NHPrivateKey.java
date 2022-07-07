package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.PrivateKey;

public interface NHPrivateKey
    extends NHKey, PrivateKey {

  short[] getSecretData();
}