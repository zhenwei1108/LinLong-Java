package com.github.zhenwei.core.pqc.crypto.gmss;

import org.bouncycastle.crypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}