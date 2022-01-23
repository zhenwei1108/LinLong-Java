package com.github.zhenwei.pkix.operator;




public interface InputExpanderProvider
{
    InputExpander get(AlgorithmIdentifier algorithm);
}