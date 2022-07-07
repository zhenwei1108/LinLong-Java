package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.util.BigIntegers;
import java.math.BigInteger;

/**
 * <pre>
 *     IValue ::= Uint16
 * </pre>
 */
public class IValue
    extends ASN1Object {

  private final BigInteger value;

  private IValue(ASN1Integer value) {
    int i = BigIntegers.intValueExact(value.getValue());

    if (i < 0 || i > 65535) {
      throw new IllegalArgumentException("value out of range");
    }

    this.value = value.getValue();
  }

  public static IValue getInstance(Object src) {
    if (src instanceof IValue) {
      return (IValue) src;
    } else if (src != null) {
      return new IValue(ASN1Integer.getInstance(src));
    }

    return null;
  }

  public ASN1Primitive toASN1Primitive() {
    return new ASN1Integer(value);
  }
}