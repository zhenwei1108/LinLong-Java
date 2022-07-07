package com.github.zhenwei.pkix.tsp.ers;

import com.github.zhenwei.pkix.operator.DigestCalculatorProvider;
import com.github.zhenwei.pkix.tsp.TSPException;
import com.github.zhenwei.pkix.util.asn1.tsp.EvidenceRecord;

public class ERSEvidenceRecordGenerator {

  private final DigestCalculatorProvider digCalcProv;

  public ERSEvidenceRecordGenerator(DigestCalculatorProvider digCalcProv) {
    this.digCalcProv = digCalcProv;
  }

  public ERSEvidenceRecord generate(ERSArchiveTimeStamp archiveTimeStamp)
      throws TSPException, ERSException {
    return new ERSEvidenceRecord(
        new EvidenceRecord(null, null, archiveTimeStamp.toASN1Structure()), digCalcProv);
  }
}