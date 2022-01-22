package com.github.zhenwei.crypto.kmip.wire;

 

public class KMIPInteger
    implements KMIPItem
{
    private final int tag;
    private final Integer value;

    public KMIPInteger(int tag, int value)
    {
        this.tag = tag;
        this.value = Integers.valueOf(value);
    }

    public int getTag()
    {
        return tag;
    }

    public byte getType()
    {
        return KMIPType.INTEGER;
    }

    public long getLength()
    {
        return 4;
    }

    public Object getValue()
    {
        return value;
    }

    public KMIPItem toKMIPItem()
    {
        return this;
    }
}