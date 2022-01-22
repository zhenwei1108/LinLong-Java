package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.BasicAgreement;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface StagedAgreement
    extends BasicAgreement
{
    AsymmetricKeyParameter calculateStage(CipherParameters pubKey);
}