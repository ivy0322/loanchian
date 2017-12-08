package org.loanchian.core;

import org.loanchian.utils.ByteArrayTool;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

/**
 * 类型
 * @author ln
 *
 */
public class KeyValue {
	
	public static final String CHARSET = "utf-8";
	
	protected String code;
	protected String name;
	protected byte[] value;
	
	public KeyValue() {
	}
	
	public KeyValue(String code, String name, byte[] value) {
		this.code = code;
		this.name = name;
		this.value = value;
	}

	public KeyValue(byte[] content) {
		try {
			int cursor = 0;
			int length = content[cursor] & 0xFF;
			cursor++;
		
			code = new String(Arrays.copyOfRange(content, cursor, cursor + length), CHARSET);
			cursor += length;
			
			length = content[cursor] & 0xFF;
			cursor++;
			
			name = new String(Arrays.copyOfRange(content, cursor, cursor + length), CHARSET);
			cursor += length;
			
			VarInt varInt = new VarInt(content, cursor);
			cursor += varInt.getOriginalSizeInBytes();
			
			value = Arrays.copyOfRange(content, cursor, (int)(cursor + varInt.value));
			
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
	
	public byte[] toByte() {
		
		ByteArrayTool byteArray = new ByteArrayTool();
		try {
			byte[] codeBytes = code.getBytes(CHARSET);
			byteArray.append(codeBytes.length);
			byteArray.append(codeBytes);
		
			byte[] nameBytes = name.getBytes(CHARSET);
			byteArray.append(nameBytes.length);
			byteArray.append(nameBytes);
			
			byteArray.append(new VarInt(value.length).encode());
			byteArray.append(value);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		return byteArray.toArray();
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public byte[] getValue() {
		return value;
	}

	public void setValue(byte[] value) {
		this.value = value;
	}
	
	public String getValueToString() {
		try {
			return new String(value, "utf-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("KeyValue [code=");
		builder.append(code);
		builder.append(", name=");
		builder.append(name);
		builder.append(", value=");
		try {
			builder.append(new String(value, "utf-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		builder.append("]");
		return builder.toString();
	}
}
