package com.github.zhenwei.provider.jce.provider;

import com.github.zhenwei.provider.jce.exception.ExtException;

public class AnnotatedException
    extends Exception
    implements ExtException {

  private Throwable _underlyingException;

  public AnnotatedException(String string, Throwable e) {
    super(string);

    _underlyingException = e;
  }

  public AnnotatedException(String string) {
    this(string, null);
  }

  Throwable getUnderlyingException() {
    return _underlyingException;
  }

  public Throwable getCause() {
    return _underlyingException;
  }
}