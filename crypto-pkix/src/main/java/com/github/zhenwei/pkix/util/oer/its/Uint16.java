package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import java.math.BigInteger;

public class Uint16
    extends ASN1Object {

  private final int value;

  public Uint16(int value) {
    this.value = verify(value);
  }

  public Uint16(BigInteger value) {
    this.value = value.intValue();
  }

  public static Uint16 getInstance(Object o) {
    if (o instanceof Uint16) {
      return (Uint16) o;
    } else {
      return new Uint16(ASN1Integer.getInstance(o).getValue());
    }
  }

  protected int verify(int value) {
    if (value < 0) {
      throw new IllegalArgumentException("Uint16 must be >= 0");
    }
    if (value > 0xFFFF) {
      throw new IllegalArgumentException("Uint16 must be <= 0xFFFF");
    }

    return value;
  }

  public ASN1Primitive toASN1Primitive() {
    return new ASN1Integer(value);
  }
}