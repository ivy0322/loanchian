package org.loanchian.wallet.utils;

import javafx.application.Platform;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Cursor;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import org.loanchian.SpringContextUtils;
import org.loanchian.consensus.ConsensusMeeting;
import org.loanchian.consensus.MiningInfos;
import org.loanchian.core.Definition;
import org.loanchian.core.TimeService;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kits.AccountKit;
import org.loanchian.listener.Listener;
import org.loanchian.wallet.entity.Point;

import java.net.URL;
import java.util.Date;

/**
 * 弹出框
 * 
 * @author ln
 *
 */
public class ConfirmDailog {

	private Stage dialogStage;
	private Stage primaryStage;
	private Label text;
	private Listener confirmListener;
	private Listener cancelListener;
	private AccountKit accountKit;
	boolean tStatus;

	public ConfirmDailog(Stage stage) {
		this(stage, "确认继续该操作吗？", 1);
	}

	/**
	 * 
	 * @param stage
	 * @param message
	 * @param type
	 *            1一般类型 2 退出类型
	 */
	public ConfirmDailog(Stage stage, String message, int type) {

		int width = 420;
		int height = 220;

		Point point = DailogUtil.getDailogPoint(width, height);

		dialogStage = new Stage();
		primaryStage = stage;
		dialogStage.initOwner(primaryStage);

		dialogStage.initModality(Modality.WINDOW_MODAL);
		dialogStage.initStyle(StageStyle.TRANSPARENT);
		dialogStage.setWidth(width);
		dialogStage.setHeight(height);
		dialogStage.setX(point.getX());
		dialogStage.setY(point.getY());
		dialogStage.setResizable(false);
		BorderPane borderPaneLayout = new BorderPane();
		borderPaneLayout.getStyleClass().add("root");
		Button confirm = new Button("确认");
		confirm.setPrefWidth(110);
		confirm.setPrefHeight(25);
		confirm.setCursor(Cursor.HAND);
		Button cancel = new Button("取消");
		cancel.setPrefWidth(110);
		cancel.setPrefHeight(25);
		cancel.setCursor(Cursor.HAND);

		confirm.setOnMouseClicked(new EventHandler<MouseEvent>() {
			public void handle(MouseEvent event) {
				dialogStage.close();
				if (confirmListener != null) {
					confirmListener.onComplete();
				}
			}
		});
		confirm.setOnKeyPressed(new EventHandler<KeyEvent>() {
			@Override
			public void handle(KeyEvent event) {
				if(event.getCode() == KeyCode.ENTER) {
					dialogStage.close();
					if (confirmListener != null) {
						confirmListener.onComplete();
					}
				}
			}
		});
		cancel.setOnMouseClicked(new EventHandler<MouseEvent>() {
			public void handle(MouseEvent event) {
				tStatus = false;
				dialogStage.close();
				if (cancelListener != null) {
					cancelListener.onComplete();
				}
			}
		});

		HBox hBox = new HBox();
		hBox.setSpacing(10);

		hBox.setAlignment(Pos.CENTER);

		VBox vBox = new VBox();
		text = new Label(message);
		text.maxWidth(80);
		text.setPadding(new Insets(0,50,0,60));
		text.setWrapText(true);
		if (type == 2) {
			Button wait = new Button("等待共识退出");
			wait.setPrefWidth(110);
			wait.setPrefHeight(25);
			confirm.setText("强制退出");
			wait.setCursor(Cursor.HAND);
			wait.setOnMouseClicked(new EventHandler<MouseEvent>() {
				@Override
				public void handle(MouseEvent event) {

					// cancel.setDisable(true);
					accountKit = LoanchainInstance.getInstance().getAccountKit();
					
					// 账户是否加密
					if (accountKit.isWalletEncrypted()) {
						// 解密账户
						URL location = getClass().getResource("/resources/template/decryptWallet.fxml");
						FXMLLoader loader = new FXMLLoader(location);
						DailogUtil.showDailog(loader, "输入钱包密码",460,250, new Callback() {
							@Override
							public void ok(Object param) {
								if (!accountKit.accountIsEncrypted(Definition.TX_VERIFY_TR)) {
									tStatus = true;
									t.start();
								}
							}
						});
					} else {
						t.start();
						tStatus = true;
					}
				}
			});
			hBox.getChildren().addAll(confirm, wait, cancel);
		} else {
			hBox.getChildren().addAll(confirm, cancel);
		}
		vBox.setSpacing(40);
		vBox.getChildren().addAll(text, hBox);
		vBox.setAlignment(Pos.CENTER);

		borderPaneLayout.setCenter(vBox);

		Scene scene = new Scene(borderPaneLayout);
		scene.getStylesheets().add("/resources/css/confirmDailog.css");
		dialogStage.setScene(scene);

	}

	Thread t = new Thread() {
		public void run() {
			while (tStatus) {
				Platform.runLater(new Runnable() {
					@Override
					public void run() {

						ConsensusMeeting consensusMeeting = SpringContextUtils.getBean(ConsensusMeeting.class);
						MiningInfos miningInfo = consensusMeeting.getMineMiningInfos();
						Date endTime = new Date(miningInfo.getEndTime() * 1000);
						Date nowTime = new Date(TimeService.currentTimeMillis());
						long time = (endTime.getTime() - nowTime.getTime()) / 1000;
						if (time <= 0) {
							text.setText("正在退出共识.");
							accountKit.quitConsensus();
							dialogStage.close();
							if (confirmListener != null) {
								confirmListener.onComplete();
							}
						}
						text.setText("正在退出，还有" + time + "秒退出.");
					}
				});
				try {
					Thread.sleep(1000l);
				} catch (InterruptedException e) {
				}
			}
		}
	};

	public void show() {
		dialogStage.show();
	}

	public void setListener(Listener confirmListener) {
		this.confirmListener = confirmListener;
	}

	public void setListener(Listener confirmListener, Listener cancelListener) {
		this.confirmListener = confirmListener;
		this.cancelListener = cancelListener;
	}
}