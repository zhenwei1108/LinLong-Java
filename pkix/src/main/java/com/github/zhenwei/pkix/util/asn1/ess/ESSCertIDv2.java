package com.github.zhenwei.pkix.util.asn1.ess;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.IssuerSerial;
import com.github.zhenwei.core.util.Arrays;

public class ESSCertIDv2
    extends ASN1Object
{
    private AlgorithmIdentifier hashAlgorithm;
    private byte[]              certHash;
    private IssuerSerial issuerSerial;
    private static final AlgorithmIdentifier DEFAULT_ALG_ID = new AlgorithmIdentifier(
        NISTObjectIdentifiers.id_sha256);

    public static ess.ESSCertIDv2 getInstance(
        Object o)
    {
        if (o instanceof ess.ESSCertIDv2)
        {
            return (ess.ESSCertIDv2) o;
        }
        else if (o != null)
        {
            return new ess.ESSCertIDv2(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private ESSCertIDv2(
        ASN1Sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        int count = 0;

        if (seq.getObjectAt(0) instanceof ASN1OctetString)
        {
            // Default value
            this.hashAlgorithm = DEFAULT_ALG_ID;
        }
        else
        {
            this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(count++).toASN1Primitive());
        }

        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(count++).toASN1Primitive()).getOctets();

        if (seq.size() > count)
        {
            this.issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(count));
        }
    }

    public ESSCertIDv2(
        byte[]              certHash)
    {
        this(null, certHash, null);
    }

    public ESSCertIDv2(
        AlgorithmIdentifier algId,
        byte[]              certHash)
    {
        this(algId, certHash, null);
    }

    public ESSCertIDv2(
        byte[]              certHash,
        IssuerSerial        issuerSerial)
    {
        this(null, certHash, issuerSerial);
    }

    public ESSCertIDv2(
        AlgorithmIdentifier algId,
        byte[]              certHash,
        IssuerSerial        issuerSerial)
    {
        if (algId == null)
        {
            // Default value
            this.hashAlgorithm = DEFAULT_ALG_ID;
        }
        else
        {
            this.hashAlgorithm = algId;
        }

        this.certHash = Arrays.clone(certHash);
        this.issuerSerial = issuerSerial;
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return this.hashAlgorithm;
    }

    public byte[] getCertHash()
    {
        return Arrays.clone(certHash);
    }

    public IssuerSerial getIssuerSerial()
    {
        return issuerSerial;
    }

    /**
     * <pre>
     * ESSCertIDv2 ::=  SEQUENCE {
     *     hashAlgorithm     AlgorithmIdentifier
     *              DEFAULT {algorithm id-sha256},
     *     certHash          Hash,
     *     issuerSerial      IssuerSerial OPTIONAL
     * }
     *
     * Hash ::= OCTET STRING
     *
     * IssuerSerial ::= SEQUENCE {
     *     issuer         GeneralNames,
     *     serialNumber   CertificateSerialNumber
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        if (!hashAlgorithm.equals(DEFAULT_ALG_ID))
        {
            v.add(hashAlgorithm);
        }

        v.add(new DEROctetString(certHash).toASN1Primitive());

        if (issuerSerial != null)
        {
            v.add(issuerSerial);
        }

        return new DERSequence(v);
    }

}