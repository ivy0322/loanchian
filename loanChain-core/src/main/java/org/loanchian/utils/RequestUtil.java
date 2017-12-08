package org.loanchian.utils;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;

public class RequestUtil {

	public static byte[] get(String url) {
		
		InputStream is = null;
		try {
			URL u = new URL(url);
			is = u.openStream();
			byte[] content = readInputStream(is);
			return content;
		} catch (Exception ex) {
			System.err.println(ex);
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		
		return null;
	}
	
	/** 
     * 从输入流中获取字节数组 
     * @param inputStream 
     * @return byte[]
     * @throws IOException 
     */  
    public static byte[] readInputStream(InputStream inputStream) throws IOException {    
        byte[] buffer = new byte[1024];    
        int len = 0;    
        ByteArrayOutputStream bos = new ByteArrayOutputStream();    
        while((len = inputStream.read(buffer)) != -1) {    
            bos.write(buffer, 0, len);    
        }    
        bos.close();    
        return bos.toByteArray();    
    }  
	
	public static String post(String url, final String param) {
		return post(url, param, null);
	}

	public static String post(String url, final String param, String encoding) {
		StringBuffer sb = new StringBuffer();
		OutputStream os = null;
		InputStream is = null;
		InputStreamReader isr = null;
		BufferedReader br = null;
		// 默认编码UTF-8
		if (StringUtil.isEmpty(encoding)) {
			encoding = "utf-8";
		}
		try {
			URL u = new URL(url);
			URLConnection connection = u.openConnection();
			connection.setDoOutput(true);
			os = connection.getOutputStream();
			os.write(param.getBytes(encoding));
			os.flush();
			is = connection.getInputStream();
			isr = new InputStreamReader(is, encoding);
			br = new BufferedReader(isr);
			String line;
			while ((line = br.readLine()) != null) {
				sb.append(line);
				sb.append("\n");
			}
		} catch (Exception ex) {
			System.err.println(ex);
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (isr != null) {
				try {
					isr.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return sb.toString();
	}

	/**
	 * get方法请求远程服务器
	 * 
	 * @param url
	 * @param encoding
	 * @return String
	 */
	public static String doGet(String url, String encoding) {
		StringBuffer sb = new StringBuffer();
		InputStreamReader is = null;
		BufferedReader br = null;
		// 默认编码UTF-8
		if (StringUtil.isEmpty(encoding)) {
			encoding = "utf-8";
		}
		try {
			URL u = new URL(url);
			is = new InputStreamReader(u.openStream(), encoding);
			br = new BufferedReader(is);
			String line;
			while ((line = br.readLine()) != null) {
				sb.append(line);
				sb.append("\n");
			}
		} catch (Exception ex) {
			System.err.println(ex);
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return sb.toString();
	}

	public static String postCustomer(String url, final String param) {
		StringBuffer sb = new StringBuffer();
		OutputStream os = null;
		InputStream is = null;
		InputStreamReader isr = null;
		BufferedReader br = null;
		String encoding = null;

		// 默认编码UTF-8
		if (StringUtil.isEmpty(encoding)) {
			encoding = "utf-8";
		}
		try {
			URL u = new URL(url);
			URLConnection connection = u.openConnection();
			connection.setRequestProperty("Content-Type", "text/html");
			connection.setDoOutput(true);
			os = connection.getOutputStream();
			os.write(param.getBytes(encoding));
			os.flush();
			is = connection.getInputStream();
			isr = new InputStreamReader(is, encoding);
			br = new BufferedReader(isr);
			String line;
			while ((line = br.readLine()) != null) {
				sb.append(line);
				sb.append("\n");
			}
		} catch (Exception ex) {
			System.err.println(ex);
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (isr != null) {
				try {
					isr.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return sb.toString();
	}
}
