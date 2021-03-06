package org.loanchian.wallet.controllers;

import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import org.loanchian.Configure;
import org.loanchian.core.Result;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kits.AccountKit;
import org.loanchian.wallet.utils.DailogUtil;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;

/**
 * 修改账户别名
 * @author ln
 *
 */
public class UpdateAliasController extends DailogController {

	public TextField aliasId;
	public Label tipId;
	public Label addressId;
	
	public Button okId;
	public Button cancelId;
	
	public void initialize() {
		
		tipId.setText("注意：修改账户别名会消耗 " + Math.abs(Configure.UPDATE_ALIAS_SUB_CREDIT) + " 点信用");
//		tipId.setStyle("-fx-text-fill: green");
		
		cancelId.setOnAction(e -> cancel());
		okId.setOnAction(e -> {
			try {
				doSave();
			} catch (UnsupportedEncodingException e1) {
				e1.printStackTrace();
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
	
	private void resetAndclose() {
		aliasId.setText("");
		close();
	}

	/*
	 * 确定
	 */
	private void doSave() throws UnsupportedEncodingException {
		
		//校验
		String alias = aliasId.getText().trim();
		if(StringUtils.isEmpty(alias)) {
			aliasId.requestFocus();
			DailogUtil.showTipDailogCenter("别名不能为空", getThisStage());
			return;
		}
		
		//修改密码并判断结果
		AccountKit accountKit = LoanchainInstance.getInstance().getAccountKit();
		
    	Result result = accountKit.updateAlias(alias);
		if(result.isSuccess()) {
    		DailogUtil.showTipDailogCenter(result.getMessage(),getThisStage());
    		resetAndclose();
    		if(callback != null) {
    			callback.ok(null);
    		}
		} else {
			log.error("修改别名失败,{}", result);
			DailogUtil.showTipDailogCenter("修改别名失败," + result.getMessage(), getThisStage());
		}
		
	}
}
