package com.github.zhenwei.core.util.test;

public interface TestResult
{
    public boolean isSuccessful();
    
    public Throwable getException();
    
    public String toString();
}