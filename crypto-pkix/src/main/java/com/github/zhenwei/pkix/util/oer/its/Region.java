package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Integer;
import java.math.BigInteger;

public class Region
    extends Uint16 {

  public Region(int value) {
    super(value);
  }

  public Region(BigInteger value) {
    super(value);
  }

  public static Region getInstance(Object o) {
    if (o instanceof Region) {
      return (Region) o;
    } else {
      return new Region(ASN1Integer.getInstance(o).getValue());
    }
  }
}