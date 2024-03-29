package com.github.zhenwei.pkix.cert.cmp;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.pkix.operator.DigestAlgorithmIdentifierFinder;
import com.github.zhenwei.pkix.operator.DigestCalculator;
import com.github.zhenwei.pkix.operator.DigestCalculatorProvider;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.util.asn1.cmp.CertStatus;
import com.github.zhenwei.pkix.util.asn1.cmp.PKIStatusInfo;
import java.math.BigInteger;

public class CertificateStatus {

  private DigestAlgorithmIdentifierFinder digestAlgFinder;
  private CertStatus certStatus;

  CertificateStatus(DigestAlgorithmIdentifierFinder digestAlgFinder, CertStatus certStatus) {
    this.digestAlgFinder = digestAlgFinder;
    this.certStatus = certStatus;
  }

  public PKIStatusInfo getStatusInfo() {
    return certStatus.getStatusInfo();
  }

  public BigInteger getCertRequestID() {
    return certStatus.getCertReqId().getValue();
  }

  public boolean isVerified(X509CertificateHolder certHolder,
      DigestCalculatorProvider digesterProvider)
      throws CMPException {
    AlgorithmIdentifier digAlg = digestAlgFinder.find(
        certHolder.toASN1Structure().getSignatureAlgorithm());
    if (digAlg == null) {
      throw new CMPException("cannot find algorithm for digest from signature");
    }

    DigestCalculator digester;

    try {
      digester = digesterProvider.get(digAlg);
    } catch (OperatorCreationException e) {
      throw new CMPException("unable to create digester: " + e.getMessage(), e);
    }

    CMPUtil.derEncodeToStream(certHolder.toASN1Structure(), digester.getOutputStream());

    return Arrays.areEqual(certStatus.getCertHash().getOctets(), digester.getDigest());
  }
}