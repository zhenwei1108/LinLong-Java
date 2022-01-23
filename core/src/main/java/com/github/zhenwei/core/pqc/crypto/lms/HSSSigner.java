package com.github.zhenwei.core.pqc.crypto.lms;

import com.github.zhenwei.core.crypto.CipherParameters;
import java.io.IOException;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class HSSSigner
    implements MessageSigner {

  private HSSPrivateKeyParameters privKey;
  private HSSPublicKeyParameters pubKey;

  public void init(boolean forSigning, CipherParameters param) {
    if (forSigning) {
      this.privKey = (HSSPrivateKeyParameters) param;
    } else {
      this.pubKey = (HSSPublicKeyParameters) param;
    }
  }

  public byte[] generateSignature(byte[] message) {
    try {
      return HSS.generateSignature(privKey, message).getEncoded();
    } catch (IOException e) {
      throw new IllegalStateException("unable to encode signature: " + e.getMessage());
    }
  }

  public boolean verifySignature(byte[] message, byte[] signature) {
    try {
      return HSS.verifySignature(pubKey, HSSSignature.getInstance(signature, pubKey.getL()),
          message);
    } catch (IOException e) {
      throw new IllegalStateException("unable to decode signature: " + e.getMessage());
    }
  }
}