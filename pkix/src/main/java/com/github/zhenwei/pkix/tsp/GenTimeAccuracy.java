package com.github.zhenwei.pkix.tsp;


import com.github.zhenwei.core.asn1.ASN1Integer;
import tsp.Accuracy;

public class GenTimeAccuracy
{
    private Accuracy accuracy;

    public GenTimeAccuracy(Accuracy accuracy)
    {
        this.accuracy = accuracy;
    }
    
    public int getSeconds()
    {
        return getTimeComponent(accuracy.getSeconds());
    }

    public int getMillis()
    {
        return getTimeComponent(accuracy.getMillis());
    }

    public int getMicros()
    {
        return getTimeComponent(accuracy.getMicros());
    }

    private int getTimeComponent(
        ASN1Integer time)
    {
        if (time != null)
        {
            return time.intValueExact();
        }

        return 0;
    }
    
    public String toString()
    {                               // digits
        return getSeconds() + "." + format(getMillis()) + format(getMicros());
    }

    private String format(int v)
    {
        if (v < 10)
        {
            return "00" + v;
        }

        if (v < 100)
        {
            return "0" + v;
        }

        return Integer.toString(v);
    }
}