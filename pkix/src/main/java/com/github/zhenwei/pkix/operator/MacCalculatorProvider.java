package com.github.zhenwei.pkix.operator;



public interface MacCalculatorProvider
{
    public MacCalculator get(AlgorithmIdentifier algorithm);
}