package com.github.zhenwei.core.crypto.agreement;

import DHUPrivateParameters;
import DHUPublicParameters;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.util.BigIntegers;
import java.math.BigInteger;


/**
 * FFC Unified static/ephemeral agreement as described in NIST SP 800-56A.
 */
public class DHUnifiedAgreement {

  private DHUPrivateParameters privParams;

  public void init(
      CipherParameters key) {
    this.privParams = (DHUPrivateParameters) key;
  }

  public int getFieldSize() {
    return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
  }

  public byte[] calculateAgreement(CipherParameters pubKey) {
    DHUPublicParameters pubParams = (DHUPublicParameters) pubKey;

    DHBasicAgreement sAgree = new DHBasicAgreement();
    DHBasicAgreement eAgree = new DHBasicAgreement();

    sAgree.init(privParams.getStaticPrivateKey());

    BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

    eAgree.init(privParams.getEphemeralPrivateKey());

    BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

    int fieldSize = getFieldSize();
    byte[] result = new byte[fieldSize * 2];
    BigIntegers.asUnsignedByteArray(eComp, result, 0, fieldSize);
    BigIntegers.asUnsignedByteArray(sComp, result, fieldSize, fieldSize);
    return result;
  }
}