package com.github.zhenwei.pkix.openssl;

/**
 * call back to allow a password to be fetched when one is requested.
 *
 * @deprecated no longer used.
 */
public interface PasswordFinder {

  public char[] getPassword();
}