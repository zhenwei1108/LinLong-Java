package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.PublicKey;
import org.bouncycastle.pqc.jcajce.interfaces.NHKey;

public interface NHPublicKey
    extends NHKey, PublicKey
{
    byte[] getPublicData();
}