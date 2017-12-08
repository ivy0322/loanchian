package org.loanchian.wallet.controllers;

import javafx.event.EventHandler;
import javafx.scene.control.Button;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import org.loanchian.core.Result;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kits.AccountKit;
import org.loanchian.wallet.utils.DailogUtil;
import org.springframework.util.StringUtils;

/**
 * 修改认证账户密码
 * @author ln
 *
 */
public class ChangeCertAccountPasswordController extends DailogController {

	public TextField oldPasswordId;
	public TextField passwordId;
	public TextField repeatId;
	
	public Button okId;
	public Button cancelId;
	
	public ToggleGroup type;

	public void initialize() {

		cancelId.setOnAction(e -> cancel());
		okId.setOnAction(e -> encryptWallet());
		oldPasswordId.setOnKeyPressed(new EventHandler<KeyEvent>() {
			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.ENTER) {
					passwordId.requestFocus();
				}
			}
		});
		oldPasswordId.setOnKeyReleased(new EventHandler<KeyEvent>() {
			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.SPACE){
					oldPasswordId.deletePreviousChar();
				}
			}
		});
		passwordId.setOnKeyPressed(new EventHandler<KeyEvent>() {
			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.ENTER) {
					repeatId.requestFocus();
				}if(event.getCode() == KeyCode.SPACE ){
					event.consume();
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
	}
	
	/*
	 * 取消
	 */
	private void cancel() {
		resetAndclose();
		if(callback != null) {
			callback.cancel(null);
		}
	}

	private void ok() {

	}
	
	/*
	 * 取消
	 */
	private void resetAndclose() {
		oldPasswordId.setText("");
		passwordId.setText("");
		repeatId.setText("");
		close();
	}

	/*
	 * 加密
	 */
	private void encryptWallet() {
		
		//校验密码
		String oldPassword = oldPasswordId.getText();
		String password = passwordId.getText();
		String passwordRepeat = repeatId.getText();
		if(StringUtils.isEmpty(oldPassword)) {
			oldPasswordId.requestFocus();
			DailogUtil.showTipDailogCenter("原密码不能为空", getThisStage());
			return;
		} else if(StringUtils.isEmpty(password)) {
			passwordId.requestFocus();
			DailogUtil.showTipDailogCenter("新密码不能为空", getThisStage());
			return;
		} else if(!password.equals(passwordRepeat)) {
			repeatId.requestFocus();
			DailogUtil.showTipDailogCenter("两次输入的新密码不一致", getThisStage());
			return;
		} else if(!validPassword(password)) {
			passwordId.requestFocus();
			DailogUtil.showTipDailogCenter("输入的密码需6位或以上，且包含字母和数字", getThisStage());
			return;
		}

		RadioButton radioButton = (RadioButton) type.getSelectedToggle();
		String type = radioButton.getId();
		
		//修改密码并判断结果
		AccountKit accountKit = LoanchainInstance.getInstance().getAccountKit();
    	Result result = accountKit.changeWalletPassword(oldPassword, password,null ,"mgpwd".equals(type) ? 1 : 2);
		if(result.isSuccess()) {
			oldPasswordId.setText("");
			passwordId.setText("");
			repeatId.setText("");
			DailogUtil.showTipDailogCenter(result.getMessage(), getThisStage());
		} else {
			log.error("密码修改失败,{}", result);
			DailogUtil.showTipDailogCenter("密码修改失败," + result.getMessage(), getThisStage());
		}
	}
}
