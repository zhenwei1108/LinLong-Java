package com.github.zhenwei.pkix.dvcs;



import cms.ContentInfo;

public abstract class DVCSMessage
{
    private final ContentInfo contentInfo;

    protected DVCSMessage(ContentInfo contentInfo)
    {
        this.contentInfo = contentInfo;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentInfo.getContentType();
    }

    public abstract ASN1Encodable getContent();
}