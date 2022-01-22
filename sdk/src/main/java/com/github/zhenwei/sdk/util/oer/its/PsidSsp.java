package com.github.zhenwei.sdk.util.oer.its;




import org.bouncycastle.oer.OEROptional;

/**
 * PsidSsp ::= SEQUENCE {
 * psid  Psid,
 * ssp   ServiceSpecificPermissions OPTIONAL
 * }
 */
public class PsidSsp
    extends ASN1Object
{
    private final Psid psid;
    private final ServiceSpecificPermissions ssp;

    public PsidSsp(Psid psid, ServiceSpecificPermissions ssp)
    {
        this.psid = psid;
        this.ssp = ssp;
    }

    public static PsidSsp getInstance(Object nextElement)
    {
        if (nextElement instanceof PsidSsp)
        {
            return (PsidSsp)nextElement;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(nextElement);

        return new PsidSsp(Psid.getInstance(seq.getObjectAt(0)),
            OEROptional.getValue(ServiceSpecificPermissions.class, seq.getObjectAt(1)));
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public Psid getPsid()
    {
        return psid;
    }

    public ServiceSpecificPermissions getSsp()
    {
        return ssp;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(psid, OEROptional.getInstance(ssp));
    }

    public static class Builder
    {

        private Psid psid;
        private ServiceSpecificPermissions ssp;

        public Builder setPsid(Psid psid)
        {
            this.psid = psid;
            return this;
        }

        public Builder setSsp(ServiceSpecificPermissions ssp)
        {
            this.ssp = ssp;
            return this;
        }

        public PsidSsp createPsidSsp()
        {
            return new PsidSsp(psid, ssp);
        }
    }
}