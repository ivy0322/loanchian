package org.loanchian.wallet.controllers;

import javafx.event.EventHandler;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import org.loanchian.core.Result;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kits.AccountKit;
import org.loanchian.wallet.utils.DailogUtil;
import org.springframework.util.StringUtils;

/**
 * 加密钱包
 * @author ln
 *
 */
public class EncryptWalletController extends DailogController {

	public TextField passwordId;
	public TextField repeatId;
	
	public Button okId;
	public Button cancelId;
	
	public void initialize() {
		cancelId.setOnAction(e -> resetAndclose());
		passwordId.setOnKeyPressed(new EventHandler<KeyEvent>() {
			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.ENTER) {
					encryptWallet();
				}
			}
		});
		passwordId.setOnKeyReleased(new EventHandler<KeyEvent>() {
			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.SPACE){
					passwordId.deletePreviousChar();
				}
			}
		});
		repeatId.setOnKeyPressed(new EventHandler<KeyEvent>() {
			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.ENTER) {
					encryptWallet();
				}
			}
		});
		repeatId.setOnKeyReleased(new EventHandler<KeyEvent>() {
			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.SPACE){
					repeatId.deletePreviousChar();
				}
			}
		});
		okId.setOnAction(e -> encryptWallet());
	}
	
	/*
	 * 取消
	 */
	private void resetAndclose() {
		passwordId.setText("");
		repeatId.setText("");
		close();
	}

	/*
	 * 加密
	 */
	private void encryptWallet() {
		
		//校验密码
		String password = passwordId.getText();
		String passwordRepeat = repeatId.getText();
		if(StringUtils.isEmpty(password)) {
			passwordId.requestFocus();
			DailogUtil.showTipDailogCenter("密码不能为空", getThisStage());
			return;
		} else if(!password.equals(passwordRepeat)) {
			repeatId.requestFocus();
			DailogUtil.showTipDailogCenter("两次输入的密码不一致", getThisStage());
			return;
		} else if(!validPassword(password)) {
			passwordId.requestFocus();
			DailogUtil.showTipDailogCenter("输入的密码需6位或以上，且包含字母和数字", getThisStage());
			return;
		}
		
		//加密并判断结果
		AccountKit accountKit = LoanchainInstance.getInstance().getAccountKit();
    	Result result = accountKit.encryptWallet(password,null);
		if(result.isSuccess()) {
    		DailogUtil.showTipDailogCenter(result.getMessage(),getThisStage());
    		resetAndclose();
		} else {
			log.error("加密钱包失败,{}", result);
			DailogUtil.showTipDailogCenter("加密钱包失败," + result.getMessage(), getThisStage());
		}
		
	}
}
