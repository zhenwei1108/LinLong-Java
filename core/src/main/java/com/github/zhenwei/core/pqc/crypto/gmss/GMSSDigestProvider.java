package com.github.zhenwei.core.pqc.crypto.gmss;


import com.github.zhenwei.core.crypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}