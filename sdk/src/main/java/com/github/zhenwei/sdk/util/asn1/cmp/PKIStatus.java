package com.github.zhenwei.sdk.util.asn1.cmp;


import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import java.math.BigInteger;

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

    public static final cmp.PKIStatus granted = new cmp.PKIStatus(GRANTED);
    public static final cmp.PKIStatus grantedWithMods = new cmp.PKIStatus(GRANTED_WITH_MODS);
    public static final cmp.PKIStatus rejection = new cmp.PKIStatus(REJECTION);
    public static final cmp.PKIStatus waiting = new cmp.PKIStatus(WAITING);
    public static final cmp.PKIStatus revocationWarning = new cmp.PKIStatus(REVOCATION_WARNING);
    public static final cmp.PKIStatus revocationNotification = new cmp.PKIStatus(REVOCATION_NOTIFICATION);
    public static final cmp.PKIStatus keyUpdateWaiting = new cmp.PKIStatus(KEY_UPDATE_WARNING);

    private ASN1Integer value;

    private PKIStatus(int value)
    {
        this(new ASN1Integer(value));
    }

    private PKIStatus(ASN1Integer value)
    {
        this.value = value;
    }

    public static cmp.PKIStatus getInstance(Object o)
    {
        if (o instanceof cmp.PKIStatus)
        {
            return (cmp.PKIStatus)o;
        }

        if (o != null)
        {
            return new cmp.PKIStatus(ASN1Integer.getInstance(o));
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