package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Integer;
import java.math.BigInteger;

/**
 * <pre>
 *     Latitude ::= NinetyDegreeInt
 * </pre>
 */
public class Latitude
    extends NinetyDegreeInt {

  public Latitude(long value) {
    super(value);
  }


  public Latitude(BigInteger value) {
    super(value);
  }

  public Latitude(byte[] bytes) {
    super(bytes);
  }

  public static Latitude getInstance(Object o) {
    if (o instanceof Latitude) {
      return (Latitude) o;
    } else if (o instanceof NinetyDegreeInt) {
      return new Latitude(((NinetyDegreeInt) o).getValue());
    } else {
      return new Latitude(ASN1Integer.getInstance(o).getValue());
    }
  }


}