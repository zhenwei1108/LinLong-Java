package com.github.zhenwei.pkix.util.asn1.cmp;



import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.Extensions;
import crmf.CertTemplate;

public class RevDetails
    extends ASN1Object
{
    private CertTemplate certDetails;
    private Extensions crlEntryDetails;

    private RevDetails(ASN1Sequence seq)
    {
        certDetails = CertTemplate.getInstance(seq.getObjectAt(0));
        if  (seq.size() > 1)
        {
            crlEntryDetails = Extensions.getInstance(seq.getObjectAt(1));
        }
    }

    public static cmp.RevDetails getInstance(Object o)
    {
        if (o instanceof cmp.RevDetails)
        {
            return (cmp.RevDetails)o;
        }

        if (o != null)
        {
            return new cmp.RevDetails(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public RevDetails(CertTemplate certDetails)
    {
        this.certDetails = certDetails;
    }

    /**
     * @deprecated use method taking Extensions
     * @param certDetails
     * @param crlEntryDetails
     */
    public RevDetails(CertTemplate certDetails, X509Extensions crlEntryDetails)
    {
        this.certDetails = certDetails;
        this.crlEntryDetails = Extensions.getInstance(crlEntryDetails.toASN1Primitive());
    }

    public RevDetails(CertTemplate certDetails, Extensions crlEntryDetails)
    {
        this.certDetails = certDetails;
        this.crlEntryDetails = crlEntryDetails;
    }

    public CertTemplate getCertDetails()
    {
        return certDetails;
    }

    public Extensions getCrlEntryDetails()
    {
        return crlEntryDetails;
    }

    /**
     * <pre>
     * RevDetails ::= SEQUENCE {
     *                  certDetails         CertTemplate,
     *                   -- allows requester to specify as much as they can about
     *                   -- the cert. for which revocation is requested
     *                   -- (e.g., for cases in which serialNumber is not available)
     *                   crlEntryDetails     Extensions       OPTIONAL
     *                   -- requested crlEntryExtensions
     *             }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(certDetails);

        if (crlEntryDetails != null)
        {
            v.add(crlEntryDetails);
        }

        return new DERSequence(v);
    }
}