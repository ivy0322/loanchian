package org.loanchian.validator;

/**
 * 验证结果
 * @author ln
 *
 */
public interface ValidatorResult<T> {
	
	/**
	 * 获取验证结果
	 * @return T
	 */
	T getResult();
}
