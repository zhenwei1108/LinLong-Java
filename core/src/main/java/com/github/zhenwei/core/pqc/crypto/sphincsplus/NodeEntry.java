package com.github.zhenwei.core.pqc.crypto.sphincsplus;

class NodeEntry
{
    final byte[] nodeValue;
    final int nodeHeight;

    NodeEntry(byte[] nodeValue, int nodeHeight)
    {
        this.nodeValue = nodeValue;
        this.nodeHeight = nodeHeight;
    }
}