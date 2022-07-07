package com.github.zhenwei.pkix.its.bc;

import com.github.zhenwei.pkix.its.ITSCertificate;
import com.github.zhenwei.pkix.its.ITSImplicitCertificateBuilder;
import com.github.zhenwei.pkix.operator.bc.BcDigestCalculatorProvider;
import com.github.zhenwei.pkix.util.oer.its.ToBeSignedCertificate;

public class BcITSImplicitCertificateBuilder
    extends ITSImplicitCertificateBuilder {

  public BcITSImplicitCertificateBuilder(ITSCertificate issuer,
      ToBeSignedCertificate.Builder tbsCertificate) {
    super(issuer, new BcDigestCalculatorProvider(), tbsCertificate);
  }
}