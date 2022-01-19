package com.github.zhenwei.sdk.util.asn1.cmc;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCFailInfo;
import org.bouncycastle.asn1.cmc.CMCStatus;
import org.bouncycastle.asn1.cmc.CMCStatusInfo;
import org.bouncycastle.asn1.cmc.PendInfo;

public class CMCStatusInfoBuilder
{
    private final CMCStatus cMCStatus;
    private final ASN1Sequence bodyList;

    private ASN1UTF8String statusString;
    private CMCStatusInfo.OtherInfo otherInfo;

    public CMCStatusInfoBuilder(CMCStatus cMCStatus, BodyPartID bodyPartID)
    {
        this.cMCStatus = cMCStatus;
        this.bodyList = new DERSequence(bodyPartID);
    }

    public CMCStatusInfoBuilder(CMCStatus cMCStatus, BodyPartID[] bodyList)
    {
        this.cMCStatus = cMCStatus;
        this.bodyList = new DERSequence(bodyList);
    }

    public org.bouncycastle.asn1.cmc.CMCStatusInfoBuilder setStatusString(String statusString)
    {
        this.statusString = new DERUTF8String(statusString);

        return this;
    }

    public org.bouncycastle.asn1.cmc.CMCStatusInfoBuilder setOtherInfo(CMCFailInfo failInfo)
    {
        this.otherInfo = new CMCStatusInfo.OtherInfo(failInfo);

        return this;
    }

    public org.bouncycastle.asn1.cmc.CMCStatusInfoBuilder setOtherInfo(PendInfo pendInfo)
    {
        this.otherInfo = new CMCStatusInfo.OtherInfo(pendInfo);

        return this;
    }

    public CMCStatusInfo build()
    {
        return new CMCStatusInfo(cMCStatus, bodyList, statusString, otherInfo);
    }
}