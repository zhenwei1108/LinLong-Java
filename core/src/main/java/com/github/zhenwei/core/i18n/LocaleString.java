package com.github.zhenwei.core.i18n;

import java.io.UnsupportedEncodingException;
import java.util.Locale;
import org.bouncycastle.i18n.LocalizedMessage;

public class LocaleString extends LocalizedMessage
{

    public LocaleString(String resource, String id)
    {
        super(resource, id);
    }
    
    public LocaleString(String resource, String id, String encoding) throws NullPointerException, UnsupportedEncodingException
    {
        super(resource, id, encoding);
    }

    public LocaleString(String resource, String id, String encoding, Object[] arguments)
        throws NullPointerException, UnsupportedEncodingException
    {
        super(resource, id, encoding, arguments);
    }
    
    public String getLocaleString(Locale locale)
    {
        return this.getEntry(null, locale, null);
    }
    
}