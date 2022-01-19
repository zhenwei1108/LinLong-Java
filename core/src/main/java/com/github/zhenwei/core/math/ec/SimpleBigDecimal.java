package com.github.zhenwei.core.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECConstants;

/**
 * Class representing a simple version of a big decimal. A
 * <code>SimpleBigDecimal</code> is basically a
 * {@link BigInteger BigInteger} with a few digits on the right of
 * the decimal point. The number of (binary) digits on the right of the decimal
 * point is called the <code>scale</code> of the <code>SimpleBigDecimal</code>.
 * Unlike in {@link java.math.BigDecimal BigDecimal}, the scale is not adjusted
 * automatically, but must be set manually. All <code>SimpleBigDecimal</code>s
 * taking part in the same arithmetic operation must have equal scale. The
 * result of a multiplication of two <code>SimpleBigDecimal</code>s returns a
 * <code>SimpleBigDecimal</code> with double scale.
 */
class SimpleBigDecimal
    //extends Number   // not in J2ME - add compatibility class?
{
    private static final long serialVersionUID = 1L;

    private final BigInteger bigInt;
    private final int scale;

    /**
     * Returns a <code>SimpleBigDecimal</code> representing the same numerical
     * value as <code>value</code>.
     * @param value The value of the <code>SimpleBigDecimal</code> to be
     * created.
     * @param scale The scale of the <code>SimpleBigDecimal</code> to be
     * created.
     * @return The such created <code>SimpleBigDecimal</code>.
     */
    public static org.bouncycastle.math.ec.SimpleBigDecimal getInstance(BigInteger value, int scale)
    {
        return new org.bouncycastle.math.ec.SimpleBigDecimal(value.shiftLeft(scale), scale);
    }

    /**
     * Constructor for <code>SimpleBigDecimal</code>. The value of the
     * constructed <code>SimpleBigDecimal</code> equals <code>bigInt /
     * 2<sup>scale</sup></code>.
     * @param bigInt The <code>bigInt</code> value parameter.
     * @param scale The scale of the constructed <code>SimpleBigDecimal</code>.
     */
    public SimpleBigDecimal(BigInteger bigInt, int scale)
    {
        if (scale < 0)
        {
            throw new IllegalArgumentException("scale may not be negative");
        }

        this.bigInt = bigInt;
        this.scale = scale;
    }

    private void checkScale(org.bouncycastle.math.ec.SimpleBigDecimal b)
    {
        if (scale != b.scale)
        {
            throw new IllegalArgumentException("Only SimpleBigDecimal of " +
                "same scale allowed in arithmetic operations");
        }
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal adjustScale(int newScale)
    {
        if (newScale < 0)
        {
            throw new IllegalArgumentException("scale may not be negative");
        }

        if (newScale == scale)
        {
            return this;
        }

        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.shiftLeft(newScale - scale),
                newScale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal add(org.bouncycastle.math.ec.SimpleBigDecimal b)
    {
        checkScale(b);
        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.add(b.bigInt), scale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal add(BigInteger b)
    {
        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.add(b.shiftLeft(scale)), scale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal negate()
    {
        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.negate(), scale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal subtract(
        org.bouncycastle.math.ec.SimpleBigDecimal b)
    {
        return add(b.negate());
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal subtract(BigInteger b)
    {
        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.subtract(b.shiftLeft(scale)),
                scale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal multiply(
        org.bouncycastle.math.ec.SimpleBigDecimal b)
    {
        checkScale(b);
        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.multiply(b.bigInt), scale + scale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal multiply(BigInteger b)
    {
        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.multiply(b), scale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal divide(
        org.bouncycastle.math.ec.SimpleBigDecimal b)
    {
        checkScale(b);
        BigInteger dividend = bigInt.shiftLeft(scale);
        return new org.bouncycastle.math.ec.SimpleBigDecimal(dividend.divide(b.bigInt), scale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal divide(BigInteger b)
    {
        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.divide(b), scale);
    }

    public org.bouncycastle.math.ec.SimpleBigDecimal shiftLeft(int n)
    {
        return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInt.shiftLeft(n), scale);
    }

    public int compareTo(org.bouncycastle.math.ec.SimpleBigDecimal val)
    {
        checkScale(val);
        return bigInt.compareTo(val.bigInt);
    }

    public int compareTo(BigInteger val)
    {
        return bigInt.compareTo(val.shiftLeft(scale));
    }

    public BigInteger floor()
    {
        return bigInt.shiftRight(scale);
    }

    public BigInteger round()
    {
        org.bouncycastle.math.ec.SimpleBigDecimal oneHalf = new org.bouncycastle.math.ec.SimpleBigDecimal(ECConstants.ONE, 1);
        return add(oneHalf.adjustScale(scale)).floor();
    }

    public int intValue()
    {
        return floor().intValue();
    }

    public long longValue()
    {
        return floor().longValue();
    }
          /* NON-J2ME compliant.
    public double doubleValue()
    {
        return Double.valueOf(toString()).doubleValue();
    }

    public float floatValue()
    {
        return Float.valueOf(toString()).floatValue();
    }
       */
    public int getScale()
    {
        return scale;
    }

    public String toString()
    {
        if (scale == 0)
        {
            return bigInt.toString();
        }

        BigInteger floorBigInt = floor();

        BigInteger fract = bigInt.subtract(floorBigInt.shiftLeft(scale));
        if (bigInt.signum() == -1)
        {
            fract = ECConstants.ONE.shiftLeft(scale).subtract(fract);
        }

        if ((floorBigInt.signum() == -1) && (!(fract.equals(ECConstants.ZERO))))
        {
            floorBigInt = floorBigInt.add(ECConstants.ONE);
        }
        String leftOfPoint = floorBigInt.toString();

        char[] fractCharArr = new char[scale];
        String fractStr = fract.toString(2);
        int fractLen = fractStr.length();
        int zeroes = scale - fractLen;
        for (int i = 0; i < zeroes; i++)
        {
            fractCharArr[i] = '0';
        }
        for (int j = 0; j < fractLen; j++)
        {
            fractCharArr[zeroes + j] = fractStr.charAt(j);
        }
        String rightOfPoint = new String(fractCharArr);

        StringBuffer sb = new StringBuffer(leftOfPoint);
        sb.append(".");
        sb.append(rightOfPoint);

        return sb.toString();
    }

    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof org.bouncycastle.math.ec.SimpleBigDecimal))
        {
            return false;
        }

        org.bouncycastle.math.ec.SimpleBigDecimal other = (org.bouncycastle.math.ec.SimpleBigDecimal)o;
        return ((bigInt.equals(other.bigInt)) && (scale == other.scale));
    }

    public int hashCode()
    {
        return bigInt.hashCode() ^ scale;
    }

}