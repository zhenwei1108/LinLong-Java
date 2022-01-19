package com.github.zhenwei.crypto.kmip.wire;

public interface KMIPItem<T>
    extends KMIPEncodable
{
    int getTag();

    byte getType();

    long getLength();

    T getValue();
}