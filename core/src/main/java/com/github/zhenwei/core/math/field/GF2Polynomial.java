package com.github.zhenwei.core.math.field;

import com.github.zhenwei.core.util.Arrays;

class GF2Polynomial implements Polynomial {

  protected final int[] exponents;

  GF2Polynomial(int[] exponents) {
    this.exponents = Arrays.clone(exponents);
  }

  public int getDegree() {
    return exponents[exponents.length - 1];
  }

  public int[] getExponentsPresent() {
    return Arrays.clone(exponents);
  }

  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof org.bouncycastle.math.field.GF2Polynomial)) {
      return false;
    }
    org.bouncycastle.math.field.GF2Polynomial other = (org.bouncycastle.math.field.GF2Polynomial) obj;
    return Arrays.areEqual(exponents, other.exponents);
  }

  public int hashCode() {
    return Arrays.hashCode(exponents);
  }
}