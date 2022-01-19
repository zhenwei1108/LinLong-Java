package com.github.zhenwei.sdk.util.asn1.cmp;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class PKIStatus
    extends ASN1Object
{
    public static final int GRANTED                 = 0;
    public static final int GRANTED_WITH_MODS       = 1;
    public static final int REJECTION               = 2;
    public static final int WAITING                 = 3;
    public static final int REVOCATION_WARNING      = 4;
    public static final int REVOCATION_NOTIFICATION = 5;
    public static final int KEY_UPDATE_WARNING      = 6;

    public static final org.bouncycastle.asn1.cmp.PKIStatus granted = new org.bouncycastle.asn1.cmp.PKIStatus(GRANTED);
    public static final org.bouncycastle.asn1.cmp.PKIStatus grantedWithMods = new org.bouncycastle.asn1.cmp.PKIStatus(GRANTED_WITH_MODS);
    public static final org.bouncycastle.asn1.cmp.PKIStatus rejection = new org.bouncycastle.asn1.cmp.PKIStatus(REJECTION);
    public static final org.bouncycastle.asn1.cmp.PKIStatus waiting = new org.bouncycastle.asn1.cmp.PKIStatus(WAITING);
    public static final org.bouncycastle.asn1.cmp.PKIStatus revocationWarning = new org.bouncycastle.asn1.cmp.PKIStatus(REVOCATION_WARNING);
    public static final org.bouncycastle.asn1.cmp.PKIStatus revocationNotification = new org.bouncycastle.asn1.cmp.PKIStatus(REVOCATION_NOTIFICATION);
    public static final org.bouncycastle.asn1.cmp.PKIStatus keyUpdateWaiting = new org.bouncycastle.asn1.cmp.PKIStatus(KEY_UPDATE_WARNING);

    private ASN1Integer value;

    private PKIStatus(int value)
    {
        this(new ASN1Integer(value));
    }

    private PKIStatus(ASN1Integer value)
    {
        this.value = value;
    }

    public static org.bouncycastle.asn1.cmp.PKIStatus getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cmp.PKIStatus)
        {
            return (org.bouncycastle.asn1.cmp.PKIStatus)o;
        }

        if (o != null)
        {
            return new org.bouncycastle.asn1.cmp.PKIStatus(ASN1Integer.getInstance(o));
        }

        return null;
    }

    public BigInteger getValue()
    {
        return value.getValue();
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }
}