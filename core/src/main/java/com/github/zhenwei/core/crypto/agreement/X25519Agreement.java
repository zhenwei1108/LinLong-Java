package com.github.zhenwei.core.crypto.agreement;


import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.params.X25519PrivateKeyParameters;
import com.github.zhenwei.core.crypto.params.X25519PublicKeyParameters;
 

;

public final class X25519Agreement
    implements RawAgreement {

  private X25519PrivateKeyParameters privateKey;

  public void init(CipherParameters parameters) {
    this.privateKey = (X25519PrivateKeyParameters) parameters;
  }

  public int getAgreementSize() {
    return X25519PrivateKeyParameters.SECRET_SIZE;
  }

  public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off) {
    privateKey.generateSecret((X25519PublicKeyParameters) publicKey, buf, off);
  }
}