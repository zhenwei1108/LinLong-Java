//package com.github.zhenwei.core.enums;
//
//public enum PKCS7Type {
//  GM(BasePkcs7TypeEnum.GmPkcs7ContentInfoTypeEnum.class),
//  STANDARD(BasePkcs7TypeEnum.Pkcs7ContentInfoTypeEnum.class)
//  ;
//
//  BasePkcs7TypeEnum[] enumConstants;
//  PKCS7Type(Class<? extends BasePkcs7TypeEnum> type) {
//    enumConstants = type.getEnumConstants();
//  }
//
//  public BasePkcs7TypeEnum[] getEnumConstants() {
//    return enumConstants;
//  }
//
//
//  public static void main(String[] args) {
//    BasePkcs7TypeEnum[] enumConstants = PKCS7Type.GM.getEnumConstants();
//    System.out.println(enumConstants);
//  }
//}
//
//
