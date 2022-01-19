package com.github.zhenwei.core.pqc.crypto.qtesla;

/**
 * Simulates pointer arithmetic.
 * A utility for porting C to Java where C code makes heavy use of pointer arithmetic.
 *
 * @Deprecated Remove when Post-Quantum Standardization project has finished and standard is published.
 */
final class IntSlicer
{
    private final int[] values;
    private int base;

    IntSlicer(int[] values, int base)
    {
        this.values = values;
        this.base = base;
    }

    final int at(int index)
    {
        return values[base + index];
    }

    final int at(int index, int value)
    {
        return values[base + index] = value;
    }


    final int at(int index, long value)
    {
        return values[base + index] = (int)value;
    }

    final org.bouncycastle.pqc.crypto.qtesla.IntSlicer from(int o)
    {
        return new org.bouncycastle.pqc.crypto.qtesla.IntSlicer(values, base + o);
    }

    final void incBase(int paramM)
    {
        base += paramM;

    }

    final org.bouncycastle.pqc.crypto.qtesla.IntSlicer copy()
    {
        return new org.bouncycastle.pqc.crypto.qtesla.IntSlicer(values, base);
    }

}