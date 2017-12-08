package org.loanchian.core;

import java.io.UnsupportedEncodingException;

public class AccountKeyValue extends KeyValue {
	
	public final static AccountKeyValue NAME = new AccountKeyValue("name", "名称");
	public final static AccountKeyValue LOGO = new AccountKeyValue("logo", "图标");

	public AccountKeyValue(String code, String name) {
		this.code = code;
		this.name = name;
	}
	
	public AccountKeyValue(String code, String name, byte[] value) {
		this.code = code;
		this.name = name;
		this.value = value;
	}
	
	public AccountKeyValue(String code, String name, String value) {
		this.code = code;
		this.name = name;
		try {
			this.value = value.getBytes(CHARSET);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
	
	public AccountKeyValue(byte[] content) {
		super(content);
	}


}
