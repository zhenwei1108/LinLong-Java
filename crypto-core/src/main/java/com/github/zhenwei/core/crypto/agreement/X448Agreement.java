package com.github.zhenwei.core.crypto.agreement;

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.RawAgreement;
import com.github.zhenwei.core.crypto.params.X448PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.X448PublicKeyParameters;

public final class X448Agreement
    implements RawAgreement {

  private X448PrivateKeyParameters privateKey;

  public void init(CipherParameters parameters) {
    this.privateKey = (X448PrivateKeyParameters) parameters;
  }

  public int getAgreementSize() {
    return X448PrivateKeyParameters.SECRET_SIZE;
  }

  public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off) {
    privateKey.generateSecret((X448PublicKeyParameters) publicKey, buf, off);
  }
}