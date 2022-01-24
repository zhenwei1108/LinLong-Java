package com.github.zhenwei.pkix.eac;

import java.io.OutputStream;
import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.DERApplicationSpecific;
import com.github.zhenwei.pkix.util.asn1.eac.CVCertificate;
import com.github.zhenwei.pkix.util.asn1.eac.CertificateBody;
import com.github.zhenwei.pkix.util.asn1.eac.CertificateHolderAuthorization;
import com.github.zhenwei.pkix.util.asn1.eac.CertificateHolderReference;
import com.github.zhenwei.pkix.util.asn1.eac.CertificationAuthorityReference;
import com.github.zhenwei.pkix.util.asn1.eac.EACTags;
import com.github.zhenwei.pkix.util.asn1.eac.PackedDate;
import com.github.zhenwei.pkix.util.asn1.eac.PublicKeyDataObject;
import com.github.zhenwei.pkix.eac.operator.EACSigner;

public class EACCertificateBuilder
{
    private static final byte [] ZeroArray = new byte [] {0};

    private PublicKeyDataObject publicKey;
    private CertificateHolderAuthorization certificateHolderAuthorization;
    private PackedDate certificateEffectiveDate;
    private PackedDate certificateExpirationDate;
    private CertificateHolderReference certificateHolderReference;
    private CertificationAuthorityReference certificationAuthorityReference;

    public EACCertificateBuilder(
        CertificationAuthorityReference certificationAuthorityReference,
        PublicKeyDataObject publicKey,
        CertificateHolderReference certificateHolderReference,
        CertificateHolderAuthorization certificateHolderAuthorization,
        PackedDate certificateEffectiveDate,
        PackedDate certificateExpirationDate)
    {
        this.certificationAuthorityReference = certificationAuthorityReference;
        this.publicKey = publicKey;
        this.certificateHolderReference = certificateHolderReference;
        this.certificateHolderAuthorization = certificateHolderAuthorization;
        this.certificateEffectiveDate = certificateEffectiveDate;
        this.certificateExpirationDate = certificateExpirationDate;
    }

    private CertificateBody buildBody()
    {
        DERApplicationSpecific  certificateProfileIdentifier;

        certificateProfileIdentifier = new DERApplicationSpecific(
                EACTags.INTERCHANGE_PROFILE, ZeroArray);

        CertificateBody body = new CertificateBody(
                certificateProfileIdentifier,
                certificationAuthorityReference,
                publicKey,
                certificateHolderReference,
                certificateHolderAuthorization,
                certificateEffectiveDate,
                certificateExpirationDate);

        return body;
    }

    public EACCertificateHolder build(EACSigner signer)
        throws EACException
    {
        try
        {
            CertificateBody body = buildBody();

            OutputStream vOut = signer.getOutputStream();

            vOut.write(body.getEncoded(ASN1Encoding.DER));

            vOut.close();

            return new EACCertificateHolder(new CVCertificate(body, signer.getSignature()));
        }
        catch (Exception e)
        {
            throw new EACException("unable to process signature: " + e.getMessage(), e);
        }
    }
}