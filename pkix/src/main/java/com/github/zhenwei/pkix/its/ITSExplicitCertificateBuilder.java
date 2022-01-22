package com.github.zhenwei.pkix.its;


import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
import com.github.zhenwei.core.asn1.sec.SECObjectIdentifiers;
import com.github.zhenwei.core.asn1.teletrust.TeleTrusTObjectIdentifiers;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.Certificate;
import org.bouncycastle.oer.its.CertificateBase;
import org.bouncycastle.oer.its.CertificateId;
import org.bouncycastle.oer.its.CertificateType;
import org.bouncycastle.oer.its.HashAlgorithm;
import org.bouncycastle.oer.its.HashedId;
import org.bouncycastle.oer.its.IssuerIdentifier;
import org.bouncycastle.oer.its.PublicVerificationKey;
import org.bouncycastle.oer.its.Signature;
import org.bouncycastle.oer.its.ToBeSignedCertificate;
import org.bouncycastle.oer.its.VerificationKeyIndicator;
import org.bouncycastle.oer.its.template.IEEE1609dot2;




public class ITSExplicitCertificateBuilder
    extends ITSCertificateBuilder
{
    private final ITSContentSigner signer;

    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    // TODO: temp constructor to get signing working.
    public ITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(tbsCertificate);
        this.signer = signer;
    }

    public ITSCertificate build(CertificateId certificateId, ITSPublicVerificationKey verificationKey)
    {
        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(CertificateId certificateId, ITSPublicVerificationKey verificationKey, ITSPublicEncryptionKey publicEncryptionKey)
    {
        ToBeSignedCertificate.Builder tbsBldr = new ToBeSignedCertificate.Builder(tbsCertificateBuilder);
        
        tbsBldr.setCertificateId(certificateId);

        if (publicEncryptionKey != null)
        {
            tbsBldr.setEncryptionKey(publicEncryptionKey.toASN1Structure());
        }

        tbsBldr.setVerificationKeyIndicator(
            VerificationKeyIndicator.builder().publicVerificationKey(verificationKey.toASN1Structure())
                .createVerificationKeyIndicator());

        ToBeSignedCertificate tbsCertificate = tbsBldr.createToBeSignedCertificate();

        ToBeSignedCertificate signerCert = null;
        VerificationKeyIndicator verificationKeyIndicator;
        if (signer.isForSelfSigning())
        {
            verificationKeyIndicator = tbsCertificate.getVerificationKeyIndicator();
        }
        else
        {
            signerCert = signer.getAssociatedCertificate().toASN1Structure().getCertificateBase().getToBeSignedCertificate();
            verificationKeyIndicator = signerCert.getVerificationKeyIndicator();
        }

        OutputStream sOut = signer.getOutputStream();

        try
        {
            sOut.write(OEREncoder.toByteArray(tbsCertificate, IEEE1609dot2.tbsCertificate));

            sOut.close();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("cannot produce certificate signature");
        }

        Signature sig = null;        // TODO: signature actually optional.
        switch (verificationKeyIndicator.getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            sig = ECDSAEncoder.toITS(SECObjectIdentifiers.secp256r1, signer.getSignature());
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            sig = ECDSAEncoder.toITS(TeleTrusTObjectIdentifiers.brainpoolP256r1, signer.getSignature());
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            sig = ECDSAEncoder.toITS(TeleTrusTObjectIdentifiers.brainpoolP384r1, signer.getSignature());
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }

        CertificateBase.Builder baseBldr = new CertificateBase.Builder();
        IssuerIdentifier.Builder issuerIdentifierBuilder = IssuerIdentifier.builder();

        ASN1ObjectIdentifier digestAlg = signer.getDigestAlgorithm().getAlgorithm();

        if (signer.isForSelfSigning())
        {

            if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
            {
                issuerIdentifierBuilder.self(HashAlgorithm.sha256);
            }
            else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
            {
                issuerIdentifierBuilder.self(HashAlgorithm.sha384);
            }
            else
            {
                throw new IllegalStateException("unknown digest");
            }
        }
        else
        {
            byte[] parentDigest = signer.getAssociatedCertificateDigest();
            HashedId.HashedId8 hashedID = new HashedId.HashedId8(Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length));
            if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
            {
                issuerIdentifierBuilder.sha256AndDigest(hashedID);
            }
            else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
            {
                issuerIdentifierBuilder.sha384AndDigest(hashedID);
            }
            else
            {
                throw new IllegalStateException("unknown digest");
            }
        }

        baseBldr.setVersion(version);
        baseBldr.setType(CertificateType.Explicit);
        baseBldr.setIssuer(issuerIdentifierBuilder.createIssuerIdentifier());

        baseBldr.setToBeSignedCertificate(tbsCertificate);
        baseBldr.setSignature(sig);

        Certificate.Builder bldr = new Certificate.Builder();

        bldr.setCertificateBase(baseBldr.createCertificateBase());

        return new ITSCertificate(bldr.createCertificate());
    }
}