package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.CipherParameters;

public interface RawAgreement
{
    void init(CipherParameters parameters);

    int getAgreementSize();

    void calculateAgreement(CipherParameters publicKey, byte[] buf, int off);
}