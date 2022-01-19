package com.github.zhenwei.sdk.util.asn1.est;

import org.bouncycastle.asn1.est.AttrOrOID;

class Utils
{
    static AttrOrOID[] clone(AttrOrOID[] ids)
    {
        AttrOrOID[] tmp = new AttrOrOID[ids.length];

        System.arraycopy(ids, 0, tmp, 0, ids.length);

        return tmp;
    }
}