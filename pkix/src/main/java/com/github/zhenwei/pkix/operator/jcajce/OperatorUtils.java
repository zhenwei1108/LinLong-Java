package com.github.zhenwei.pkix.operator.jcajce;

import com.github.zhenwei.pkix.operator.GenericKey;
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;

class OperatorUtils {

  static Key getJceKey(GenericKey key) {
    if (key.getRepresentation() instanceof Key) {
      return (Key) key.getRepresentation();
    }

    if (key.getRepresentation() instanceof byte[]) {
      return new SecretKeySpec((byte[]) key.getRepresentation(), "ENC");
    }

    throw new IllegalArgumentException("unknown generic key type");
  }
}