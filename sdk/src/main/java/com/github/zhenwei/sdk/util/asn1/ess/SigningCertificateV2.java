package com.github.zhenwei.sdk.util.asn1.ess;






import PolicyInformation;

public class SigningCertificateV2
    extends ASN1Object
{
    ASN1Sequence certs;
    ASN1Sequence policies;

    public static ess.SigningCertificateV2 getInstance(
        Object o)
    {
        if (o == null || o instanceof ess.SigningCertificateV2)
        {
            return (ess.SigningCertificateV2) o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new ess.SigningCertificateV2((ASN1Sequence) o);
        }

        return null;
    }

    private SigningCertificateV2(
        ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.certs = ASN1Sequence.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1)
        {
            this.policies = ASN1Sequence.getInstance(seq.getObjectAt(1));
        }
    }

    public SigningCertificateV2(
        ESSCertIDv2 cert)
    {
        this.certs = new DERSequence(cert);
    }

    public SigningCertificateV2(
        ESSCertIDv2[] certs)
    {
        this.certs = new DERSequence(certs);
    }

    public SigningCertificateV2(
        ESSCertIDv2[] certs,
        PolicyInformation[] policies)
    {
        this.certs = new DERSequence(certs);

        if (policies != null)
        {
            this.policies = new DERSequence(policies);
        }
    }

    public ESSCertIDv2[] getCerts()
    {
        ESSCertIDv2[] certIds = new ESSCertIDv2[certs.size()];
        for (int i = 0; i != certs.size(); i++)
        {
            certIds[i] = ESSCertIDv2.getInstance(certs.getObjectAt(i));
        }
        return certIds;
    }

    public PolicyInformation[] getPolicies()
    {
        if (policies == null)
        {
            return null;
        }

        PolicyInformation[] policyInformations = new PolicyInformation[policies.size()];
        for (int i = 0; i != policies.size(); i++)
        {
            policyInformations[i] = PolicyInformation.getInstance(policies.getObjectAt(i));
        }
        return policyInformations;
    }

    /**
     * The definition of SigningCertificateV2 is
     * <pre>
     * SigningCertificateV2 ::=  SEQUENCE {
     *      certs        SEQUENCE OF ESSCertIDv2,
     *      policies     SEQUENCE OF PolicyInformation OPTIONAL
     * }
     * </pre>
     * id-aa-signingCertificateV2 OBJECT IDENTIFIER ::= { iso(1)
     *    member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *    smime(16) id-aa(2) 47 }
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(certs);

        if (policies != null)
        {
            v.add(policies);
        }

        return new DERSequence(v);
    }
}