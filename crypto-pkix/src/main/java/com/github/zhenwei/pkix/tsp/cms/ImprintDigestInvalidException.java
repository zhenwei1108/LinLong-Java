package com.github.zhenwei.pkix.tsp.cms;

import com.github.zhenwei.pkix.tsp.TimeStampToken;

public class ImprintDigestInvalidException
    extends Exception {

  private TimeStampToken token;

  public ImprintDigestInvalidException(String message, TimeStampToken token) {
    super(message);

    this.token = token;
  }

  public TimeStampToken getTimeStampToken() {
    return token;
  }
}