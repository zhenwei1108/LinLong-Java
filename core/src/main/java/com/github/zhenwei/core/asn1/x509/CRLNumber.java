package com.github.zhenwei.core.asn1.x509;

import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.util.BigIntegers;
import java.math.BigInteger;

/**
 * The CRLNumber object.
 * <pre>
 * CRLNumber::= INTEGER(0..MAX)
 * </pre>
 */
public class CRLNumber
    extends ASN1Object {

  private BigInteger number;

  public CRLNumber(
      BigInteger number) {
    if (BigIntegers.ZERO.compareTo(number) > 0) {
      throw new IllegalArgumentException("Invalid CRL number : not in (0..MAX)");
    }
    this.number = number;
  }

  public BigInteger getCRLNumber() {
    return number;
  }

  public String toString() {
    return "CRLNumber: " + getCRLNumber();
  }

  public ASN1Primitive toASN1Primitive() {
    return new ASN1Integer(number);
  }

  public static CRLNumber getInstance(Object o) {
    if (o instanceof CRLNumber) {
      return (CRLNumber) o;
    } else if (o != null) {
      return new CRLNumber(ASN1Integer.getInstance(o).getValue());
    }

    return null;
  }
}