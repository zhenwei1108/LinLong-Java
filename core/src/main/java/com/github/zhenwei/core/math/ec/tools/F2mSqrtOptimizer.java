package com.github.zhenwei.core.math.ec.tools;


import com.github.zhenwei.core.asn1.x9.ECNamedCurveTable;
import com.github.zhenwei.core.asn1.x9.X9ECParameters;
import com.github.zhenwei.core.crypto.ec.CustomNamedCurves;
import com.github.zhenwei.core.math.ec.ECAlgorithms;
import com.github.zhenwei.core.math.ec.ECFieldElement;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;
 
 


public class F2mSqrtOptimizer
{
    public static void main(String[] args)
    {
        SortedSet names = new TreeSet(enumToList(ECNamedCurveTable.getNames()));
        names.addAll(enumToList(CustomNamedCurves.getNames()));

        Iterator it = names.iterator();
        while (it.hasNext())
        {
            String name = (String)it.next();
            X9ECParameters x9 = CustomNamedCurves.getByName(name);
            if (x9 == null)
            {
                x9 = ECNamedCurveTable.getByName(name);
            }
            if (x9 != null && ECAlgorithms.isF2mCurve(x9.getCurve()))
            {
                System.out.print(name + ":");
                implPrintRootZ(x9);
            }
        }
    }

    public static void printRootZ(X9ECParameters x9)
    {
        if (!ECAlgorithms.isF2mCurve(x9.getCurve()))
        {
            throw new IllegalArgumentException("Sqrt optimization only defined over characteristic-2 fields");
        }

        implPrintRootZ(x9);
    }

    private static void implPrintRootZ(X9ECParameters x9)
    {
        ECFieldElement z = getCurve().fromBigInteger(BigInteger.valueOf(2));
        ECFieldElement rootZ = z.sqrt();

        System.out.println(rootZ.toBigInteger().toString(16).toUpperCase());

        if (!rootZ.square().equals(z))
        {
            throw new IllegalStateException("Optimized-sqrt sanity check failed");
        }
    }

    private static ArrayList enumToList(Enumeration en)
    {
        ArrayList rv = new ArrayList();
        while (en.hasMoreElements())
        {
            rv.add(en.nextElement());
        }
        return rv;
    }
}