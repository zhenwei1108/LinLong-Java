package com.github.zhenwei.sdk.enums.exception;

public interface IExceptionEnum {

  /**
   * @author zhangzhenwei
   * @description 参数错误
   * @date 2022/2/11 21:55
   */
  String params_err = "params error";

  /**
   * @author zhangzhenwei
   * @description 系统内部错误
   * @date 2022/2/11 21:55
   */
  String system_err = "system error";

  /**
   * 暂不支持
   */
  String not_support_now = "not support now";
  /**
   * @return java.lang.String
   * @author zhangzhenwei
   * @description 获取异常信息
   * @date 2022/1/28 22:50
   */
  String getMessage();

  /**
   * @return java.lang.String
   * @author zhangzhenwei
   * @description 获取异常描述
   * @date 2022/1/28 22:50
   */
  String getDesc();

}