package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Integer;
import java.math.BigInteger;

/**
 * <pre>
 *     Latitude ::= OneEightyDegreeInt
 *
 *     OneEightyDegreeInt ::= INTEGER {
 *     min          (-1799999999),
 *     max          (1800000000),
 *     unknown      (1800000001)
 *   } (-1799999999..1800000001)
 * </pre>
 */
public class Longitude
    extends OneEightyDegreeInt {

  public Longitude(long value) {
    super(value);
  }


  public Longitude(BigInteger value) {
    super(value);
  }

  public Longitude(byte[] bytes) {
    super(bytes);
  }

  public static Longitude getInstance(Object o) {
    if (o instanceof Longitude) {
      return (Longitude) o;
    } else if (o instanceof OneEightyDegreeInt) {
      return new Longitude(((OneEightyDegreeInt) o).getValue());
    } else {
      return new Longitude(ASN1Integer.getInstance(o).getValue());
    }
  }

}