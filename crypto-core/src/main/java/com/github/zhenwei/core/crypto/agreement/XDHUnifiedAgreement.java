package com.github.zhenwei.core.crypto.agreement;

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.RawAgreement;
import com.github.zhenwei.core.crypto.params.XDHUPrivateParameters;
import com.github.zhenwei.core.crypto.params.XDHUPublicParameters;

public class XDHUnifiedAgreement
    implements RawAgreement {

  private final RawAgreement xAgreement;

  private XDHUPrivateParameters privParams;

  public XDHUnifiedAgreement(RawAgreement xAgreement) {
    this.xAgreement = xAgreement;
  }

  public void init(
      CipherParameters key) {
    this.privParams = (XDHUPrivateParameters) key;
  }

  public int getAgreementSize() {
    return xAgreement.getAgreementSize() * 2;
  }

  public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off) {
    XDHUPublicParameters pubParams = (XDHUPublicParameters) publicKey;

    xAgreement.init(privParams.getEphemeralPrivateKey());

    xAgreement.calculateAgreement(pubParams.getEphemeralPublicKey(), buf, off);

    xAgreement.init(privParams.getStaticPrivateKey());

    xAgreement.calculateAgreement(pubParams.getStaticPublicKey(), buf,
        off + xAgreement.getAgreementSize());
  }
}