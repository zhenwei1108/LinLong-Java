package com.github.zhenwei.core.i18n.filter;

import org.bouncycastle.i18n.filter.UntrustedInput;

/**
 * 
 * Wrapper class to mark an untrusted Url
 */
public class UntrustedUrlInput extends UntrustedInput
{
    public UntrustedUrlInput(Object url)
    {
        super(url);
    }
    
}