package com.github.zhenwei.provider.jce.interfaces;

import javax.crypto.interfaces.DHKey;
import ElGamalParameterSpec;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}