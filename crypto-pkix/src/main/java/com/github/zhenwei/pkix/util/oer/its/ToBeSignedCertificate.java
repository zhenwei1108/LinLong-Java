package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Null;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.pkix.util.oer.OEROptional;
import java.util.Iterator;

/**
 * <pre>
 *     ToBeSignedCertificate ::= SEQUENCE {
 *     id                      CertificateId,
 *     cracaId                 HashedId3,
 *     crlSeries               CrlSeries,
 *     validityPeriod          ValidityPeriod,
 *     region                  GeographicRegion OPTIONAL,
 *     assuranceLevel          SubjectAssurance OPTIONAL,
 *     appPermissions          SequenceOfPsidSsp OPTIONAL,
 *     certIssuePermissions    SequenceOfPsidGroupPermissions OPTIONAL,
 *     certRequestPermissions  SequenceOfPsidGroupPermissions OPTIONAL,
 *     canRequestRollover      NULL OPTIONAL,
 *     encryptionKey           PublicEncryptionKey OPTIONAL,
 *     verifyKeyIndicator      VerificationKeyIndicator,
 *     ...
 *   }
 *   (WITH COMPONENTS { ..., appPermissions PRESENT} |
 *    WITH COMPONENTS { ..., certIssuePermissions PRESENT} |
 *    WITH COMPONENTS { ..., certRequestPermissions PRESENT})
 * </pre>
 */
public class ToBeSignedCertificate
    extends ASN1Object {

  private final CertificateId certificateId;
  private final HashedId cracaId;
  private final CrlSeries crlSeries;
  private final ValidityPeriod validityPeriod;
  private final GeographicRegion geographicRegion;
  private final SubjectAssurance assuranceLevel;
  private final SequenceOfPsidSsp appPermissions;
  private final SequenceOfPsidGroupPermissions certIssuePermissions;
  private final SequenceOfPsidGroupPermissions certRequestPermissions;
  private final ASN1Null canRequestRollover;
  private final PublicEncryptionKey encryptionKey;
  private final VerificationKeyIndicator verificationKeyIndicator;


  public ToBeSignedCertificate(CertificateId certificateId,
      HashedId cracaId,
      CrlSeries crlSeries,
      ValidityPeriod validityPeriod,
      GeographicRegion geographicRegion,
      SubjectAssurance assuranceLevel,
      SequenceOfPsidSsp appPermissions,
      SequenceOfPsidGroupPermissions certIssuePermissions,
      SequenceOfPsidGroupPermissions certRequestPermissions,
      ASN1Null canRequestRollover,
      PublicEncryptionKey encryptionKey,
      VerificationKeyIndicator verificationKeyIndicator) {
    this.certificateId = certificateId;
    this.cracaId = cracaId;
    this.crlSeries = crlSeries;
    this.validityPeriod = validityPeriod;
    this.geographicRegion = geographicRegion;
    this.assuranceLevel = assuranceLevel;
    this.appPermissions = appPermissions;
    this.certIssuePermissions = certIssuePermissions;
    this.certRequestPermissions = certRequestPermissions;
    this.canRequestRollover = canRequestRollover;
    this.encryptionKey = encryptionKey;
    this.verificationKeyIndicator = verificationKeyIndicator;
  }

  public static ToBeSignedCertificate getInstance(Object o) {
    if (o == null || o instanceof ToBeSignedCertificate) {
      return (ToBeSignedCertificate) o;
    }

    Iterator<ASN1Encodable> seq = ASN1Sequence.getInstance(o).iterator();
    return new Builder()
        .setCertificateId(CertificateId.getInstance(seq.next()))
        .setCracaId(HashedId.getInstance(seq.next()))
        .setCrlSeries(CrlSeries.getInstance(seq.next()))
        .setValidityPeriod(ValidityPeriod.getInstance(seq.next()))
        .setGeographicRegion(OEROptional.getValue(GeographicRegion.class, seq.next()))
        .setAssuranceLevel(OEROptional.getValue(SubjectAssurance.class, seq.next()))
        .setAppPermissions(OEROptional.getValue(SequenceOfPsidSsp.class, seq.next()))
        .setCertIssuePermissions(
            OEROptional.getValue(SequenceOfPsidGroupPermissions.class, seq.next()))
        .setCertRequestPermissions(
            OEROptional.getValue(SequenceOfPsidGroupPermissions.class, seq.next()))
        .setCanRequestRollover(OEROptional.getValue(ASN1Null.class, seq.next()))
        .setEncryptionKey(OEROptional.getValue(PublicEncryptionKey.class, seq.next()))
        .setVerificationKeyIndicator(VerificationKeyIndicator.getInstance(seq.next()))
        .createToBeSignedCertificate();

  }


  public CertificateId getCertificateId() {
    return certificateId;
  }

  public HashedId getCracaId() {
    return cracaId;
  }

  public CrlSeries getCrlSeries() {
    return crlSeries;
  }

  public ValidityPeriod getValidityPeriod() {
    return validityPeriod;
  }

  public GeographicRegion getGeographicRegion() {
    return geographicRegion;
  }

  public SubjectAssurance getAssuranceLevel() {
    return assuranceLevel;
  }

  public SequenceOfPsidSsp getAppPermissions() {
    return appPermissions;
  }

  public SequenceOfPsidGroupPermissions getCertIssuePermissions() {
    return certIssuePermissions;
  }

  public SequenceOfPsidGroupPermissions getCertRequestPermissions() {
    return certRequestPermissions;
  }

  public ASN1Null getCanRequestRollover() {
    return canRequestRollover;
  }

  public PublicEncryptionKey getEncryptionKey() {
    return encryptionKey;
  }

  public VerificationKeyIndicator getVerificationKeyIndicator() {
    return verificationKeyIndicator;
  }

  /**
   * <pre>
   * ToBeSignedCertificate ::= SEQUENCE  {
   * id                     CertificateId,
   * cracaId                HashedId3,
   * crlSeries              CrlSeries,
   * validityPeriod         ValidityPeriod,
   * region                 GeographicRegion OPTIONAL,
   * assuranceLevel         SubjectAssurance OPTIONAL,
   * appPermissions         SequenceOfPsidSsp OPTIONAL,
   * certIssuePermissions   SequenceOfPsidGroupPermissions OPTIONAL,
   * certRequestPermissions SequenceOfPsidGroupPermissions OPTIONAL,
   * canRequestRollover     NULL OPTIONAL,
   * encryptionKey          PublicEncryptionKey OPTIONAL,
   * verifyKeyIndicator     VerificationKeyIndicator,
   * ...
   * }
   * (WITH COMPONENTS { ..., appPermissions PRESENT} |
   * WITH COMPONENTS { ..., certIssuePermissions PRESENT} |
   * WITH COMPONENTS { ..., certRequestPermissions PRESENT})
   * </pre>
   */
  public ASN1Primitive toASN1Primitive() {
    return Utils.toSequence(
        certificateId,
        cracaId,
        crlSeries,
        validityPeriod,
        OEROptional.getInstance(geographicRegion),
        OEROptional.getInstance(assuranceLevel),
        OEROptional.getInstance(appPermissions),
        OEROptional.getInstance(certIssuePermissions),
        OEROptional.getInstance(certRequestPermissions),
        OEROptional.getInstance(canRequestRollover),
        OEROptional.getInstance(encryptionKey),
        verificationKeyIndicator);
  }


  public static class Builder {

    private CertificateId certificateId;
    private HashedId cracaId;
    private CrlSeries crlSeries;
    private ValidityPeriod validityPeriod;
    private GeographicRegion geographicRegion;
    private SubjectAssurance assuranceLevel;
    private SequenceOfPsidSsp appPermissions;
    private SequenceOfPsidGroupPermissions certIssuePermissions;
    private SequenceOfPsidGroupPermissions certRequestPermissions;
    private ASN1Null canRequestRollover;
    private PublicEncryptionKey encryptionKey;
    private VerificationKeyIndicator verificationKeyIndicator;

    public Builder() {
    }

    public Builder(Builder o) {
      this.certificateId = o.certificateId;
      this.cracaId = o.cracaId;
      this.crlSeries = o.crlSeries;
      this.validityPeriod = o.validityPeriod;
      this.geographicRegion = o.geographicRegion;
      this.assuranceLevel = o.assuranceLevel;
      this.appPermissions = o.appPermissions;
      this.certIssuePermissions = o.certIssuePermissions;
      this.certRequestPermissions = o.certRequestPermissions;
      this.canRequestRollover = o.canRequestRollover;
      this.encryptionKey = o.encryptionKey;
      this.verificationKeyIndicator = o.verificationKeyIndicator;
    }

    public Builder(ToBeSignedCertificate o) {
      this.certificateId = o.certificateId;
      this.cracaId = o.cracaId;
      this.crlSeries = o.crlSeries;
      this.validityPeriod = o.validityPeriod;
      this.geographicRegion = o.geographicRegion;
      this.assuranceLevel = o.assuranceLevel;
      this.appPermissions = o.appPermissions;
      this.certIssuePermissions = o.certIssuePermissions;
      this.certRequestPermissions = o.certRequestPermissions;
      this.canRequestRollover = o.canRequestRollover;
      this.encryptionKey = o.encryptionKey;
      this.verificationKeyIndicator = o.verificationKeyIndicator;
    }


    public Builder setCertificateId(CertificateId certificateId) {
      this.certificateId = certificateId;
      return this;
    }

    public Builder setCracaId(HashedId cracaId) {
      this.cracaId = cracaId;
      return this;
    }

    public Builder setCrlSeries(CrlSeries crlSeries) {
      this.crlSeries = crlSeries;
      return this;
    }

    public Builder setValidityPeriod(ValidityPeriod validityPeriod) {
      this.validityPeriod = validityPeriod;
      return this;
    }

    public Builder setGeographicRegion(GeographicRegion geographicRegion) {
      this.geographicRegion = geographicRegion;
      return this;
    }

    public Builder setAssuranceLevel(SubjectAssurance assuranceLevel) {
      this.assuranceLevel = assuranceLevel;
      return this;
    }

    public Builder setAppPermissions(SequenceOfPsidSsp appPermissions) {
      this.appPermissions = appPermissions;
      return this;
    }

    public Builder setCertIssuePermissions(SequenceOfPsidGroupPermissions certIssuePermissions) {
      this.certIssuePermissions = certIssuePermissions;
      return this;
    }

    public Builder setCertRequestPermissions(
        SequenceOfPsidGroupPermissions certRequestPermissions) {
      this.certRequestPermissions = certRequestPermissions;
      return this;
    }

    public Builder setCanRequestRollover(ASN1Null canRequestRollover) {
      this.canRequestRollover = canRequestRollover;
      return this;
    }

    public Builder setEncryptionKey(PublicEncryptionKey encryptionKey) {
      this.encryptionKey = encryptionKey;
      return this;
    }

    public Builder setVerificationKeyIndicator(VerificationKeyIndicator verificationKeyIndicator) {
      this.verificationKeyIndicator = verificationKeyIndicator;
      return this;
    }

    public ToBeSignedCertificate createToBeSignedCertificate() {
      return new ToBeSignedCertificate(
          certificateId,
          cracaId,
          crlSeries,
          validityPeriod,
          geographicRegion,
          assuranceLevel,
          appPermissions,
          certIssuePermissions,
          certRequestPermissions,
          canRequestRollover,
          encryptionKey,
          verificationKeyIndicator);
    }
  }
}