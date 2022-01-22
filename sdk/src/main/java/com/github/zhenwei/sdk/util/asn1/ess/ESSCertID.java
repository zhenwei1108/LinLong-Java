package com.github.zhenwei.sdk.util.asn1.ess;










public class ESSCertID
    extends ASN1Object
{
    private ASN1OctetString certHash;

    private IssuerSerial issuerSerial;

    public static ess.ESSCertID getInstance(Object o)
    {
        if (o instanceof ess.ESSCertID)
        {
            return (ess.ESSCertID)o;
        }
        else if (o != null)
        {
            return new ess.ESSCertID(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * constructor
     */
    private ESSCertID(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
 
        if (seq.size() > 1)
        {
            issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
        }
    }

    public ESSCertID(
        byte[]          hash)
    {
        certHash = new DEROctetString(hash);
    }

    public ESSCertID(
        byte[]          hash,
        IssuerSerial    issuerSerial)
    {
        this.certHash = new DEROctetString(hash);
        this.issuerSerial = issuerSerial;
    }

    public byte[] getCertHash()
    {
        return certHash.getOctets();
    }

    public IssuerSerial getIssuerSerial()
    {
        return issuerSerial;
    }

    /**
     * <pre>
     * ESSCertID ::= SEQUENCE {
     *     certHash Hash, 
     *     issuerSerial IssuerSerial OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        
        v.add(certHash);
        
        if (issuerSerial != null)
        {
            v.add(issuerSerial);
        }

        return new DERSequence(v);
    }
}