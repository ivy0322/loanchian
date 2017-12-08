package org.loanchian.wallet.utils;

public abstract class Callback {
	public abstract void ok(Object param);
	public void cancel(Object param) {}
}
