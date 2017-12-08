package org.loanchian.wallet.controllers;

import javafx.event.EventHandler;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import org.loanchian.core.Result;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kits.AccountKit;
import org.loanchian.wallet.utils.DailogUtil;
import org.springframework.util.StringUtils;

/**
 * 解密钱包
 * @author ln
 *
 */
public class DecryptWalletController extends DailogController {

	public TextField passwordId;
	
	public Button okId;
	
	public void initialize() {
		passwordId.setOnKeyPressed(new EventHandler<KeyEvent>() {

			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.ENTER) {
					decryptWallet();
				}
			}
		});
		okId.setOnAction(e -> decryptWallet());
	}
	
	/*
	 * 取消
	 */
	private void resetAndclose() {
		passwordId.setText("");
		close();
	}

	/*
	 * 解密
	 */
	private void decryptWallet() {
		
		//校验密码
		String password = passwordId.getText();
		if(StringUtils.isEmpty(password)) {
			passwordId.requestFocus();
			DailogUtil.showTipDailogCenter("密码不能为空", getThisStage());
			return;
		} else if(!validPassword(password)) {
			passwordId.requestFocus();
			DailogUtil.showTipDailogCenter("密码错误", getThisStage());
			return;
		}
		
		//解密钱包并判断结果
		AccountKit accountKit = LoanchainInstance.getInstance().getAccountKit();
    	Result result = accountKit.decryptAccount(password, null,2);
		if(result.isSuccess()) {
    		resetAndclose();
    		if(callback != null) {
    			callback.ok(null);
    		}
		} else {
			log.error("解密钱包失败,{}", result);
			DailogUtil.showTipDailogCenter(result.getMessage(), getThisStage());
		}
		
	}
}
