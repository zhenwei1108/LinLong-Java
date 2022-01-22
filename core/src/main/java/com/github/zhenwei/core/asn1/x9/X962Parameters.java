package com.github.zhenwei.core.asn1.x9;


import ASN1Null;
import com.github.zhenwei.core.asn1.ASN1Choice;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;


/**
 * The Parameters ASN.1 CHOICE from 62.
 */
public class X962Parameters
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1Primitive params = null;

    public static X962Parameters getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof X962Parameters)
        {
            return  (X962Parameters)obj;
        }
        
        if (obj instanceof ASN1Primitive)
        {
            return new X962Parameters((ASN1Primitive)obj);
        }

        if (obj instanceof byte[])
        {
            try
            {
                return new X962Parameters(ASN1Primitive.fromByteArray((byte[])obj));
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("unable to parse encoded data: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("unknown object in getInstance()");
    }
    
    public static X962Parameters getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject()); // must be explicitly tagged
    }
    
    public X962Parameters(
        X9ECParameters      ecParameters)
    {
        this.params = ecParameters.toASN1Primitive();
    }

    public X962Parameters(
        ASN1ObjectIdentifier namedCurve)
    {
        this.params = namedCurve;
    }

    public X962Parameters(
        ASN1Null           obj)
    {
        this.params = obj;
    }

    private X962Parameters(ASN1Primitive obj)
    {
        this.params = obj;
    }

    public boolean isNamedCurve()
    {
        return (params instanceof ASN1ObjectIdentifier);
    }

    public boolean isImplicitlyCA()
    {
        return (params instanceof ASN1Null);
    }

    public ASN1Primitive getParameters()
    {
        return params;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * Parameters ::= CHOICE {
     *    ecParameters ECParameters,
     *    namedCurve   CURVES.&amp;id({CurveNames}),
     *    implicitlyCA NULL
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return params;
    }
}