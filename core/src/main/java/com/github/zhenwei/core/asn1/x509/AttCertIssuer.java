package com.github.zhenwei.core.asn1.x509;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.V2Form;

public class AttCertIssuer
    extends ASN1Object
    implements ASN1Choice
{
    ASN1Encodable   obj;
    ASN1Primitive choiceObj;
    
    public static org.bouncycastle.asn1.x509.AttCertIssuer getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof org.bouncycastle.asn1.x509.AttCertIssuer)
        {
            return (org.bouncycastle.asn1.x509.AttCertIssuer)obj;
        }
        else if (obj instanceof V2Form)
        {
            return new org.bouncycastle.asn1.x509.AttCertIssuer(V2Form.getInstance(obj));
        }
        else if (obj instanceof GeneralNames)
        {
            return new org.bouncycastle.asn1.x509.AttCertIssuer((GeneralNames)obj);
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new org.bouncycastle.asn1.x509.AttCertIssuer(V2Form.getInstance((ASN1TaggedObject)obj, false));
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new org.bouncycastle.asn1.x509.AttCertIssuer(GeneralNames.getInstance(obj));
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }
    
    public static org.bouncycastle.asn1.x509.AttCertIssuer getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject()); // must be explicitly tagged
    }

    /**
     * Don't use this one if you are trying to be RFC 3281 compliant.
     * Use it for v1 attribute certificates only.
     * 
     * @param names our GeneralNames structure
     */
    public AttCertIssuer(
        GeneralNames  names)
    {
        obj = names;
        choiceObj = obj.toASN1Primitive();
    }
    
    public AttCertIssuer(
        V2Form  v2Form)
    {
        obj = v2Form;
        choiceObj = new DERTaggedObject(false, 0, obj);
    }

    public ASN1Encodable getIssuer()
    {
        return obj;
    }
    
    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  AttCertIssuer ::= CHOICE {
     *       v1Form   GeneralNames,  -- MUST NOT be used in this
     *                               -- profile
     *       v2Form   [0] V2Form     -- v2 only
     *  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return choiceObj;
    }
}