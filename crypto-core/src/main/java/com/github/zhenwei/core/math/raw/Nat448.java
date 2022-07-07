package com.github.zhenwei.core.math.raw;

import com.github.zhenwei.core.util.Pack;
import java.math.BigInteger;

public abstract class Nat448 {

  public static void copy64(long[] x, long[] z) {
    z[0] = x[0];
    z[1] = x[1];
    z[2] = x[2];
    z[3] = x[3];
    z[4] = x[4];
    z[5] = x[5];
    z[6] = x[6];
  }

  public static void copy64(long[] x, int xOff, long[] z, int zOff) {
    z[zOff + 0] = x[xOff + 0];
    z[zOff + 1] = x[xOff + 1];
    z[zOff + 2] = x[xOff + 2];
    z[zOff + 3] = x[xOff + 3];
    z[zOff + 4] = x[xOff + 4];
    z[zOff + 5] = x[xOff + 5];
    z[zOff + 6] = x[xOff + 6];
  }

  public static long[] create64() {
    return new long[7];
  }

  public static long[] createExt64() {
    return new long[14];
  }

  public static boolean eq64(long[] x, long[] y) {
    for (int i = 6; i >= 0; --i) {
      if (x[i] != y[i]) {
        return false;
      }
    }
    return true;
  }

  public static long[] fromBigInteger64(BigInteger x) {
    if (x.signum() < 0 || x.bitLength() > 448) {
      throw new IllegalArgumentException();
    }

    long[] z = create64();

    // NOTE: Use a fixed number of loop iterations
    for (int i = 0; i < 7; ++i) {
      z[i] = x.longValue();
      x = x.shiftRight(64);
    }
    return z;
  }

  public static boolean isOne64(long[] x) {
    if (x[0] != 1L) {
      return false;
    }
    for (int i = 1; i < 7; ++i) {
      if (x[i] != 0L) {
        return false;
      }
    }
    return true;
  }

  public static boolean isZero64(long[] x) {
    for (int i = 0; i < 7; ++i) {
      if (x[i] != 0L) {
        return false;
      }
    }
    return true;
  }

  public static void mul(int[] x, int[] y, int[] zz) {
    Nat224.mul(x, y, zz);
    Nat224.mul(x, 7, y, 7, zz, 14);

    int c21 = Nat224.addToEachOther(zz, 7, zz, 14);
    int c14 = c21 + Nat224.addTo(zz, 0, zz, 7, 0);
    c21 += Nat224.addTo(zz, 21, zz, 14, c14);

    int[] dx = Nat224.create(), dy = Nat224.create();
    boolean neg = Nat224.diff(x, 7, x, 0, dx, 0) != Nat224.diff(y, 7, y, 0, dy, 0);

    int[] tt = Nat224.createExt();
    Nat224.mul(dx, dy, tt);

    c21 += neg ? Nat.addTo(14, tt, 0, zz, 7) : Nat.subFrom(14, tt, 0, zz, 7);
    Nat.addWordAt(28, c21, zz, 21);
  }

  public static void square(int[] x, int[] zz) {
    Nat224.square(x, zz);
    Nat224.square(x, 7, zz, 14);

    int c21 = Nat224.addToEachOther(zz, 7, zz, 14);
    int c14 = c21 + Nat224.addTo(zz, 0, zz, 7, 0);
    c21 += Nat224.addTo(zz, 21, zz, 14, c14);

    int[] dx = Nat224.create();
    Nat224.diff(x, 7, x, 0, dx, 0);

    int[] tt = Nat224.createExt();
    Nat224.square(dx, tt);

    c21 += Nat.subFrom(14, tt, 0, zz, 7);
    Nat.addWordAt(28, c21, zz, 21);
  }

  public static BigInteger toBigInteger64(long[] x) {
    byte[] bs = new byte[56];
    for (int i = 0; i < 7; ++i) {
      long x_i = x[i];
      if (x_i != 0L) {
        Pack.longToBigEndian(x_i, bs, (6 - i) << 3);
      }
    }
    return new BigInteger(1, bs);
  }
}