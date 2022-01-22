package com.github.zhenwei.sdk.util.asn1.cmc;






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

    public cmc.CMCStatusInfoBuilder setStatusString(String statusString)
    {
        this.statusString = new DERUTF8String(statusString);

        return this;
    }

    public cmc.CMCStatusInfoBuilder setOtherInfo(CMCFailInfo failInfo)
    {
        this.otherInfo = new CMCStatusInfo.OtherInfo(failInfo);

        return this;
    }

    public cmc.CMCStatusInfoBuilder setOtherInfo(PendInfo pendInfo)
    {
        this.otherInfo = new CMCStatusInfo.OtherInfo(pendInfo);

        return this;
    }

    public CMCStatusInfo build()
    {
        return new CMCStatusInfo(cMCStatus, bodyList, statusString, otherInfo);
    }
}