package com.github.zhenwei.core.math.ec.custom.sec;


import com.github.zhenwei.core.math.ec.AbstractECLookupTable;
import com.github.zhenwei.core.math.ec.ECConstants;
import com.github.zhenwei.core.math.ec.ECCurve;
import com.github.zhenwei.core.math.ec.ECCurve.AbstractF2m;
import com.github.zhenwei.core.math.ec.ECFieldElement;
import com.github.zhenwei.core.math.ec.ECLookupTable;
import com.github.zhenwei.core.math.ec.ECPoint;
import com.github.zhenwei.core.math.raw.Nat256;
import com.github.zhenwei.core.util.encoders.Hex;
import java.math.BigInteger;


public class SecT233R1Curve extends AbstractF2m {

  private static final int SECT233R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;
  private static final ECFieldElement[] SECT233R1_AFFINE_ZS = new ECFieldElement[]{
      new SecT233FieldElement(
          ECConstants.ONE)};

  protected SecT233R1Point infinity;

  public SecT233R1Curve() {
    super(233, 74, 0, 0);

    this.infinity = new SecT233R1Point(this, null, null);

    this.a = fromBigInteger(BigInteger.valueOf(1));
    this.b = fromBigInteger(new BigInteger(1,
        Hex.decodeStrict("0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD")));
    this.order = new BigInteger(1,
        Hex.decodeStrict("01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7"));
    this.cofactor = BigInteger.valueOf(2);

    this.coord = SECT233R1_DEFAULT_COORDS;
  }

  protected ECCurve cloneCurve() {
    return new SecT233R1Curve();
  }

  public boolean supportsCoordinateSystem(int coord) {
    switch (coord) {
      case COORD_LAMBDA_PROJECTIVE:
        return true;
      default:
        return false;
    }
  }

  public int getFieldSize() {
    return 233;
  }

  public ECFieldElement fromBigInteger(BigInteger x) {
    return new SecT233FieldElement(x);
  }

  protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y) {
    return new SecT233R1Point(this, x, y);
  }

  protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs) {
    return new SecT233R1Point(this, x, y, zs);
  }

  public ECPoint getInfinity() {
    return infinity;
  }

  public boolean isKoblitz() {
    return false;
  }

  public int getM() {
    return 233;
  }

  public boolean isTrinomial() {
    return true;
  }

  public int getK1() {
    return 74;
  }

  public int getK2() {
    return 0;
  }

  public int getK3() {
    return 0;
  }

  public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len) {
    final int FE_LONGS = 4;

    final long[] table = new long[len * FE_LONGS * 2];
    {
      int pos = 0;
      for (int i = 0; i < len; ++i) {
        ECPoint p = points[off + i];
        Nat256.copy64(((SecT233FieldElement) p.getRawXCoord()).x, 0, table, pos);
        pos += FE_LONGS;
        Nat256.copy64(((SecT233FieldElement) p.getRawYCoord()).x, 0, table, pos);
        pos += FE_LONGS;
      }
    }

    return new AbstractECLookupTable() {
      public int getSize() {
        return len;
      }

      public ECPoint lookup(int index) {
        long[] x = Nat256.create64(), y = Nat256.create64();
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
        long[] x = Nat256.create64(), y = Nat256.create64();
        int pos = index * FE_LONGS * 2;

        for (int j = 0; j < FE_LONGS; ++j) {
          x[j] = table[pos + j];
          y[j] = table[pos + FE_LONGS + j];
        }

        return createPoint(x, y);
      }

      private ECPoint createPoint(long[] x, long[] y) {
        return createRawPoint(new SecT233FieldElement(x), new SecT233FieldElement(y),
            SECT233R1_AFFINE_ZS);
      }
    };
  }
}