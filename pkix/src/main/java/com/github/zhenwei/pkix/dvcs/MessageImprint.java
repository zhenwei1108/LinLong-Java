package com.github.zhenwei.pkix.dvcs;


import  DigestInfo;

public class MessageImprint
{
    private final DigestInfo messageImprint;

    public MessageImprint(DigestInfo messageImprint)
    {
        this.messageImprint = messageImprint;
    }

    public DigestInfo toASN1Structure()
    {
        return messageImprint;
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof org.bouncycastle.dvcs.MessageImprint)
        {
            return messageImprint.equals(((org.bouncycastle.dvcs.MessageImprint)o).messageImprint);
        }

        return false;
    }

    public int hashCode()
    {
        return messageImprint.hashCode();
    }
}