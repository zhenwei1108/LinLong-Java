package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Integer;
import java.math.BigInteger;

public class Psid
    extends ASN1Integer {

  public Psid(long value) {
    super(value);
    validate();
  }


  public Psid(BigInteger value) {
    super(value);
    validate();
  }

  public Psid(byte[] bytes) {
    super(bytes);
    validate();
  }

  public static Psid getInstance(Object o) {
    if (o instanceof Psid) {
      return (Psid) o;
    }
    return new Psid(ASN1Integer.getInstance(o).getValue());
  }

  private void validate() {
    if (BigInteger.ZERO.compareTo(getValue()) >= 0) {
      throw new IllegalStateException("psid must be greater than zero");
    }
  }
}