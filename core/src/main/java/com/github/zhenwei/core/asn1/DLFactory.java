package com.github.zhenwei.core.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;

class DLFactory
{
    static final DLSequence EMPTY_SEQUENCE = new DLSequence();
    static final DLSet EMPTY_SET = new DLSet();

    static DLSequence createSequence(ASN1EncodableVector v)
    {
        if (v.size() < 1)
        {
            return EMPTY_SEQUENCE;
        }

        return new DLSequence(v);
    }

    static DLSet createSet(ASN1EncodableVector v)
    {
        if (v.size() < 1)
        {
            return EMPTY_SET;
        }

        return new DLSet(v);
    }
}