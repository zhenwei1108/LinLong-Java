package com.github.zhenwei.sdk.util.asn1.dvcs;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;


/**
 * ServiceType ::= ENUMERATED { cpd(1), vsd(2), cpkc(3), ccpd(4) }
 */

public class ServiceType
    extends ASN1Object
{
    /**
     * Identifier of CPD service (Certify Possession of Data).
     */
    public static final org.bouncycastle.asn1.dvcs.ServiceType CPD = new org.bouncycastle.asn1.dvcs.ServiceType(1);

    /**
     * Identifier of VSD service (Verify Signed Document).
     */
    public static final org.bouncycastle.asn1.dvcs.ServiceType VSD = new org.bouncycastle.asn1.dvcs.ServiceType(2);

    /**
     * Identifier of VPKC service (Verify Public Key Certificates (also referred to as CPKC)).
     */
    public static final org.bouncycastle.asn1.dvcs.ServiceType VPKC = new org.bouncycastle.asn1.dvcs.ServiceType(3);

    /**
     * Identifier of CCPD service (Certify Claim of Possession of Data).
     */
    public static final org.bouncycastle.asn1.dvcs.ServiceType CCPD = new org.bouncycastle.asn1.dvcs.ServiceType(4);

    private ASN1Enumerated value;

    public ServiceType(int value)
    {
        this.value = new ASN1Enumerated(value);
    }

    private ServiceType(ASN1Enumerated value)
    {
        this.value = value;
    }

    public static org.bouncycastle.asn1.dvcs.ServiceType getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.dvcs.ServiceType)
        {
            return (org.bouncycastle.asn1.dvcs.ServiceType)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.dvcs.ServiceType(ASN1Enumerated.getInstance(obj));
        }

        return null;
    }

    public static org.bouncycastle.asn1.dvcs.ServiceType getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Enumerated.getInstance(obj, explicit));
    }

    public BigInteger getValue()
    {
        return value.getValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }

    public String toString()
    {
        int num = value.intValueExact();
        return "" + num + (
            num == CPD.value.intValueExact() ? "(CPD)" :
                num == VSD.value.intValueExact() ? "(VSD)" :
                    num == VPKC.value.intValueExact() ? "(VPKC)" :
                        num == CCPD.value.intValueExact() ? "(CCPD)" :
                            "?");
    }

}