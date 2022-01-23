package com.github.zhenwei.core.pqc.crypto.lms;

import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.util.Encodable;
import java.io.IOException;


public abstract class LMSKeyParameters
    extends AsymmetricKeyParameter
    implements Encodable {

  protected LMSKeyParameters(boolean isPrivateKey) {
    super(isPrivateKey);
  }

  abstract public byte[] getEncoded()
      throws IOException;
}