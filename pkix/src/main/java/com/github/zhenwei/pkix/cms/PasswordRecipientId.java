package com.github.zhenwei.pkix.cms;

public class PasswordRecipientId
    extends RecipientId
{
    /**
     * Construct a recipient ID of the password type.
     */
    public PasswordRecipientId()
    {
        super(password);
    }

    public int hashCode()
    {
        return password;
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof org.bouncycastle.cms.PasswordRecipientId))
        {
            return false;
        }

        return true;
    }

    public Object clone()
    {
        return new org.bouncycastle.cms.PasswordRecipientId();
    }

    public boolean match(Object obj)
    {
        if (obj instanceof PasswordRecipientInformation)
        {
            return true;
        }
        
        return false;
    }
}