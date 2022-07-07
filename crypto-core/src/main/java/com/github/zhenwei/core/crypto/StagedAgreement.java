package com.github.zhenwei.core.crypto;

import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;

public interface StagedAgreement
    extends BasicAgreement {

  AsymmetricKeyParameter calculateStage(CipherParameters pubKey);
}