package com.github.zhenwei.provider.jce;


import java.util.Enumeration;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import x9.X9ECParameters;

/**
 * a table of locally supported named curves.
 */
public class ECNamedCurveTable
{
    /**
     * return a parameter spec representing the passed in named
     * curve. The routine returns null if the curve is not present.
     * 
     * @param name the name of the curve requested
     * @return a parameter spec for the curve, null if it is not available.
     */
    public static ECNamedCurveParameterSpec getParameterSpec(
        String  name)
    {
        X9ECParameters  ecP = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName(name);
        if (ecP == null)
        {
            try
            {
                ecP = org.bouncycastle.crypto.ec.CustomNamedCurves.getByOID(new ASN1ObjectIdentifier(name));
            }
            catch (IllegalArgumentException e)
            {
                // ignore - not an oid
            }

            if (ecP == null)
            {
                ecP = x9.ECNamedCurveTable.getByName(name);
                if (ecP == null)
                {
                    try
                    {
                        ecP = x9.ECNamedCurveTable.getByOID(new ASN1ObjectIdentifier(name));
                    }
                    catch (IllegalArgumentException e)
                    {
                        // ignore - not an oid
                    }
                }
            }
        }

        if (ecP == null)
        {
            return null;
        }

        return new ECNamedCurveParameterSpec(
                                        name,
                                        ecP.getCurve(),
                                        ecP.getG(),
                                        ecP.getN(),
                                        ecP.getH(),
                                        ecP.getSeed());
    }

    /**
     * return an enumeration of the names of the available curves.
     *
     * @return an enumeration of the names of the available curves.
     */
    public static Enumeration getNames()
    {
        return x9.ECNamedCurveTable.getNames();
    }
}