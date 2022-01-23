package com.github.zhenwei.core.math.ec.custom.sec;


import com.github.zhenwei.core.math.ec.AbstractECLookupTable;
import com.github.zhenwei.core.math.ec.ECConstants;
import com.github.zhenwei.core.math.ec.ECCurve;
import com.github.zhenwei.core.math.ec.ECCurve.AbstractF2m;
import com.github.zhenwei.core.math.ec.ECFieldElement;
import com.github.zhenwei.core.math.ec.ECLookupTable;
import com.github.zhenwei.core.math.ec.ECMultiplier;
import com.github.zhenwei.core.math.ec.ECPoint;
import com.github.zhenwei.core.math.ec.WTauNafMultiplier;
import com.github.zhenwei.core.math.raw.Nat576;
import com.github.zhenwei.core.util.encoders.Hex;
import java.math.BigInteger;


public class SecT571K1Curve extends AbstractF2m {

  private static final int SECT571K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;
  private static final ECFieldElement[] SECT571K1_AFFINE_ZS = new ECFieldElement[]{
      new SecT571FieldElement(
          ECConstants.ONE)};

  protected SecT571K1Point infinity;

  public SecT571K1Curve() {
    super(571, 2, 5, 10);

    this.infinity = new SecT571K1Point(this, null, null);

    this.a = fromBigInteger(BigInteger.valueOf(0));
    this.b = fromBigInteger(BigInteger.valueOf(1));
    this.order = new BigInteger(1, Hex.decodeStrict(
        "020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001"));
    this.cofactor = BigInteger.valueOf(4);

    this.coord = SECT571K1_DEFAULT_COORDS;
  }

  protected ECCurve cloneCurve() {
    return new SecT571K1Curve();
  }

  public boolean supportsCoordinateSystem(int coord) {
    switch (coord) {
      case COORD_LAMBDA_PROJECTIVE:
        return true;
      default:
        return false;
    }
  }

  protected ECMultiplier createDefaultMultiplier() {
    return new WTauNafMultiplier();
  }

  public int getFieldSize() {
    return 571;
  }

  public ECFieldElement fromBigInteger(BigInteger x) {
    return new SecT571FieldElement(x);
  }

  protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
    return new SecT571K1Point(this, x, y);
  }

  protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
    return new SecT571K1Point(this, x, y, zs);
  }

  public ECPoint getInfinity() {
    return infinity;
  }

  public boolean isKoblitz() {
    return true;
  }

  public int getM() {
    return 571;
  }

  public boolean isTrinomial() {
    return false;
  }

  public int getK1() {
    return 2;
  }

  public int getK2() {
    return 5;
  }

  public int getK3() {
    return 10;
  }

  public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
    final int FE_LONGS = 9;

    final long[] table = new long[len * FE_LONGS * 2];
    {
      int pos = 0;
      for (int i = 0; i < len; ++i) {
        ECPoint p = points[off + i];
        Nat576.copy64(((SecT571FieldElement) p.getRawXCoord()).x, 0, table, pos);
        pos += FE_LONGS;
        Nat576.copy64(((SecT571FieldElement) p.getRawYCoord()).x, 0, table, pos);
        pos += FE_LONGS;
      }
    }

    return new AbstractECLookupTable() {
      public int getSize() {
        return len;
      }

      public ECPoint lookup(int index) {
        long[] x = Nat576.create64(), y = Nat576.create64();
        int pos = 0;

        for (int i = 0; i < len; ++i) {
          long MASK = ((i ^ index) - 1) >> 31;

          for (int j = 0; j < FE_LONGS; ++j) {
            x[j] ^= table[pos + j] & MASK;
            y[j] ^= table[pos + FE_LONGS + j] & MASK;
          }

          pos += (FE_LONGS * 2);
        }

        return createPoint(x, y);
      }

      public ECPoint lookupVar(int index) {
        long[] x = Nat576.create64(), y = Nat576.create64();
        int pos = index * FE_LONGS * 2;

        for (int j = 0; j < FE_LONGS; ++j) {
          x[j] = table[pos + j];
          y[j] = table[pos + FE_LONGS + j];
        }

        return createPoint(x, y);
      }

      private ECPoint createPoint(long[] x, long[] y) {
        return createRawPoint(new SecT571FieldElement(x), new SecT571FieldElement(y),
            SECT571K1_AFFINE_ZS);
      }
    };
  }
}