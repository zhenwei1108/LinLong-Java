package com.github.zhenwei.pkix.tsp.ers;

import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TSPException;
import tsp.EvidenceRecord;

public class ERSEvidenceRecordGenerator
{
    private final DigestCalculatorProvider digCalcProv;

    public ERSEvidenceRecordGenerator(DigestCalculatorProvider digCalcProv)
    {
        this.digCalcProv = digCalcProv;
    }

    public ERSEvidenceRecord generate(ERSArchiveTimeStamp archiveTimeStamp)
        throws TSPException, ERSException
    {
        return new ERSEvidenceRecord(
            new EvidenceRecord(null, null, archiveTimeStamp.toASN1Structure()), digCalcProv);
    }
}