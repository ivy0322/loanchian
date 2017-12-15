package org.loanchian.core;

import org.loanchian.message.Message;

/**
 * 下载数据结果
 * @author ln
 *
 */
public class GetDataResult extends Result {

	//结果
	private Message data;

	public GetDataResult(boolean success) {
		this.success = success;
	}
	
	public GetDataResult(Message data, boolean success) {
		this.data = data;
		this.success = success;
	}
	
	public Message getData() {
		return data;
	}
}
