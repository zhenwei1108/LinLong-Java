package com.github.zhenwei.core.math.ec.custom.sec;


import com.github.zhenwei.core.math.ec.AbstractECLookupTable;
import com.github.zhenwei.core.math.ec.ECConstants;
import com.github.zhenwei.core.math.ec.ECCurve;
import com.github.zhenwei.core.math.ec.ECFieldElement;
import com.github.zhenwei.core.math.ec.ECLookupTable;
import com.github.zhenwei.core.math.raw.Nat160;
import com.github.zhenwei.core.util.encoders.Hex;
import java.math.BigInteger;
import java.security.SecureRandom;



public class SecP160R2Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = SecP160R2FieldElement.Q;

    private static final int SECP160R2_DEFAULT_COORDS = COORD_JACOBIAN;
    private static final ECFieldElement[] SECP160R2_AFFINE_ZS = new ECFieldElement[] { new SecP160R2FieldElement(
        ECConstants.ONE) };

    protected SecP160R2Point infinity;

    public SecP160R2Curve()
    {
        super(q);

        this.infinity = new SecP160R2Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decodeStrict("B4E134D3FB59EB8BAB57274904664D5AF50388BA")));
        this.order = new BigInteger(1, Hex.decodeStrict("0100000000000000000000351EE786A818F3A1A16B"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SECP160R2_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP160R2Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_JACOBIAN:
            return true;
        default:
            return false;
        }
    }

    public BigInteger getQ()
    {
        return q;
    }

    public int getFieldSize()
    {
        return q.bitLength();
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecP160R2FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecP160R2Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecP160R2Point(this, x, y, zs);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_INTS = 5;

        final int[] table = new int[len * FE_INTS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat160.copy(((SecP160R2FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat160.copy(((SecP160R2FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
            }
        }

        return new AbstractECLookupTable()
        {
            public int getSize()
            {
                return len;
            }

            public ECPoint lookup(int index)
            {
                int[] x = Nat160.create(), y = Nat160.create();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    int MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_INTS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_INTS + j] & MASK;
                    }

                    pos += (FE_INTS * 2);
                }

                return createPoint(x, y);
            }

            public ECPoint lookupVar(int index)
            {
                int[] x = Nat160.create(), y = Nat160.create();
                int pos = index * FE_INTS * 2;

                for (int j = 0; j < FE_INTS; ++j)
                {
                    x[j] = table[pos + j];
                    y[j] = table[pos + FE_INTS + j];
                }

                return createPoint(x, y);
            }

            private ECPoint createPoint(int[] x, int[] y)
            {
                return createRawPoint(new SecP160R2FieldElement(x), new SecP160R2FieldElement(y), SECP160R2_AFFINE_ZS);
            }
        };
    }

    public ECFieldElement randomFieldElement(SecureRandom r)
    {
        int[] x = Nat160.create();
        SecP160R2Field.random(r, x);
        return new SecP160R2FieldElement(x);
    }

    public ECFieldElement randomFieldElementMult(SecureRandom r)
    {
        int[] x = Nat160.create();
        SecP160R2Field.randomMult(r, x);
        return new SecP160R2FieldElement(x);
    }
}