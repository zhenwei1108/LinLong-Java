package org.sdk.crypto.exception;

public class CryptoSDKException extends RuntimeException {

  private String message = "内部错误";
  private int code = 99999;

  public CryptoSDKException() {
  }

  public CryptoSDKException(String message) {
    super(message);
    this.message = message;
  }

  public CryptoSDKException(Throwable throwable) {
    super(throwable);
    this.message = throwable.getMessage();
  }

  public CryptoSDKException(String message, Throwable throwable) {
    super(message, throwable);
    this.message = message;
  }

  public CryptoSDKException(String message, int code) {
    super(message);
    this.message = message;
    this.code = code;
  }

  public CryptoSDKException(IException iException) {
    super(iException.getMessage());
    this.message = iException.getMessage();
    this.code = iException.getCode();
  }

  public CryptoSDKException(IException iException, Throwable throwable) {
    super(throwable);
    this.message = iException.getMessage();
    this.code = iException.getCode();
  }


}
