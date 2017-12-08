package org.loanchian.wallet;

import java.awt.AWTException;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.TrayIcon.MessageType;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.URL;

import javax.swing.ImageIcon;

import org.loanchian.SpringContextUtils;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kits.AccountKit;
import org.loanchian.listener.Listener;
import org.loanchian.service.SystemStatusService;
import org.loanchian.wallet.controllers.MainController;
import org.loanchian.wallet.controllers.StartPageController;
import org.loanchian.wallet.listener.WindowCloseEvent;
import org.loanchian.wallet.utils.ConfirmDailog;
import org.loanchian.wallet.utils.TipsWindows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

/**
 * 印链桌面客户端（钱包）
 * @author ln
 *
 */
public class Main extends Decoration implements ActionListener {

	private static final Logger log = LoggerFactory.getLogger(Main.class);

	//如果系统支持托盘， 在第一次点击关闭按钮时，最小化到托盘，弹出提示
	private boolean hideTip;

	private TrayIcon trayIcon;

	private Stage stage;

	private Stage startPageStage;

	private MainController mainController;

	/**
	 * 程序入口
	 * @param args
	 */
	public static void main(String[] args) {
		launch(args);
	}

	/**
	 * 启动方法
	 */
	@Override
	public void start(final Stage stage) throws Exception {
		super.start(stage);

		Context.addStage("main", stage);
		this.stage = stage;

		//设置程序标题
		stage.setTitle(Constant.APP_TITLE);

		//设置程序图标
		//stage.getIcons().add(new Image(getClass().getResourceAsStream(Constant.APP_ICON)));
		if (isMac()) {
			java.awt.Image dockIcon = new ImageIcon(getClass().getResource(Constant.APP_ICON)).getImage();
			try {
				Class<?> cls = Class.forName("com.apple.eawt.Application");
				Object application = cls.newInstance().getClass().getMethod("getApplication").invoke(null);
				application.getClass().getMethod("setDockIconImage", java.awt.Image.class).invoke(application, dockIcon);
			} catch (Exception  e) {
			}

		} else {
			//设置程序标题
			stage.setTitle(Constant.APP_TITLE);
			//设置程序图标
			stage.getIcons().add(new Image(getClass().getResourceAsStream(Constant.APP_ICON)));
		}

		//初始化系统托盘
		initSystemTray();

		//初始化容器
		initContainer();

		//初始化监听器
		initListener();

		showOnStartPage(stage);
	}

	TipsWindows tips = null;
	private void showRealPage() throws IOException {
		//显示界面
		show();
		//增加一个修复监听器，如果发生数据修复情况，则弹出提示框
		Thread t = new Thread() {
			@Override
			public void run() {
				SystemStatusService systemStatusService = SpringContextUtils.getBean(SystemStatusService.class);
				boolean repair = false;

				while(true) {
					boolean nowStatus = systemStatusService.isDataReset();
					if(repair && !nowStatus) {
						repair = false;
						Platform.runLater(new Runnable() {
							@Override
							public void run() {
								//关闭
								tips.close();
								tips = null;
							}
						});
					} else if(!repair && nowStatus) {
						repair = true;
						Platform.runLater(new Runnable() {
							@Override
							public void run() {
								if(tips == null) {
									tips = new TipsWindows(null, "数据修复中，请耐心等待···");
								}
								//显示
								tips.show();
							}
						});
					}
					try {
						Thread.sleep(1000l);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}
		};
		t.setName("data repair monitor");
		t.start();
	}

	//显示启动界面
	private void showOnStartPage(final Stage stage) throws IOException {


		URL location = getClass().getResource("/resources/template/startPage.fxml");
		FXMLLoader loader = new FXMLLoader(location);

		Pane mainUI = loader.load();

		final StartPageController startPageController = loader.getController();
		startPageController.setListener(new Listener() {
			@Override
			public void onComplete() {
				Platform.runLater(new Runnable() {
					@Override
					public void run() {
						try {
							startPageStage.close();
							showRealPage();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				});
			}
		});

		startPageController.setMainController(mainController);
		Platform.runLater(new Runnable() {
			@Override
			public void run() {
				startPageController.init();
			}
		});

		startPageStage = new Stage(StageStyle.UNDECORATED);
		Context.addStage("startPage", startPageStage);
		Scene scene = new Scene(mainUI);
		scene.getStylesheets().add("/resources/css/startPage.css");
		startPageStage.initOwner(stage);
		startPageStage.setScene(scene);

		startPageStage.getIcons().add(new Image(getClass().getResourceAsStream(Constant.APP_ICON)));
		startPageStage.show();
	}

	/**
	 * 停止
	 */
	@Override
	public void stop() throws Exception {
		super.stop();
		LoanchainInstance.getInstance().shutdown();
		System.exit(0);
	}

	/*
	 * 初始化界面容器
	 */
	private void initContainer() throws IOException {

		//初始化菜单
		initMenu();

		URL location = getClass().getResource("/resources/template/main.fxml");
		FXMLLoader loader = new FXMLLoader(location);

		Pane mainUI = loader.load();

		mainController = loader.getController();
		mainController.setStage(stage);
		mainController.setDecorationController(decorationController);
		mainContent.getChildren().add(mainUI);
	}

	/*
	 * 初始化菜单
	 */
	private void initMenu() {

	}

	/*
     * 初始化监听器
     */
	private void initListener() {
		//当点击"X"关闭窗口按钮时，如果系统支持托盘，则最小化到托盘，否则关闭
		stage.addEventHandler(WindowCloseEvent.ACTION, event -> {
			if(!(event instanceof WindowCloseEvent)) {
				return;
			}
			if(SystemTray.isSupported()) {
				//隐藏，可双击托盘恢复
				hide();
				if(!hideTip && !isMac()) {
					hideTip = true;
					TrayIcon[] trayIcons = SystemTray.getSystemTray().getTrayIcons();
					if(trayIcons != null && trayIcons.length > 0) {
						trayIcons[0].displayMessage("温馨提示", "印链客户端已最小化到系统托盘，双击可再次显示", MessageType.INFO);
					}
				}
			} else {
				//退出程序
				exit();
			}
		});
	}

	private boolean isMac() {
		String osName = System.getProperty("os.name").toLowerCase();
		return osName.indexOf("mac") != -1;
	}

	/*
     * 初始化系统托盘
     */
	private void initSystemTray() {
		//判断系统是否支持托盘功能
		if(SystemTray.isSupported()) {
			//获得托盘图标图片路径
			URL resource = this.getClass().getResource(Constant.APP_ICON);
			trayIcon = new TrayIcon(new ImageIcon(resource).getImage(), Constant.TRAY_DESC, createMenu());
			//设置双击动作标识
			trayIcon.setActionCommand("db_click_tray");
			//托盘双击监听
			trayIcon.addActionListener(this);
			//图标自动适应
			trayIcon.setImageAutoSize(true);

			SystemTray sysTray = SystemTray.getSystemTray();
			try {
				sysTray.add(trayIcon);
			} catch (AWTException e) {
				log.error(e.getMessage(), e);
			}
		}
	}

	/*
     * 创建托盘菜单
     */
	private PopupMenu createMenu() {
		PopupMenu popupMenu = new PopupMenu(); //创建弹出菜单对象

		//创建弹出菜单中的显示主窗体项.
		MenuItem itemShow = new MenuItem("显示");
		itemShow.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				show();
			}
		});

		popupMenu.add(itemShow);
		popupMenu.addSeparator();

		//创建弹出菜单中的退出项
		MenuItem itemExit = new MenuItem("退出系统");
		popupMenu.add(itemExit);

		//给退出系统添加事件监听
		itemExit.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				exit();
			}
		});


		return popupMenu;
	}

	/**
	 * 事件监听处理
	 */
	@Override
	public void actionPerformed(ActionEvent e) {

		String command = e.getActionCommand();

		if("db_click_tray".equals(command) && !stage.isIconified()) {
			//双击托盘，显示窗体
			//多次使用显示和隐藏设置false
			if (stage.isShowing()) {
				hide();
			} else {
				show();
			}
		}
	}

	/**
	 * 显示窗口
	 */
	public void show() {
		Platform.setImplicitExit(false);
		Platform.runLater(new Runnable() {
			@Override
			public void run() {
				stage.show();
			}
		});
	}

	/**
	 * 隐藏窗口
	 */
	public void hide() {
		Platform.runLater(new Runnable() {
			@Override
			public void run() {
				stage.hide();
			}
		});
	}

	/**
	 * 程序退出
	 */
	public void exit() {
		AccountKit accountKit = LoanchainInstance.getInstance().getAccountKit();
		//当前共识状态，是否正在共识中
		boolean consensusStatus = accountKit.checkIsConsensusingPackager(null);
		if(consensusStatus) {
			Platform.runLater(new Runnable() {
				@Override
				public void run() {
					ConfirmDailog dailog = new ConfirmDailog(Context.getMainStage(),"您当前正在共识中，确认要退出共识吗？",2);
					dailog.setListener(new Listener() {
						@Override
						public void onComplete() {
							SystemTray.getSystemTray().remove(trayIcon);
							Platform.exit();
						}
					});
					dailog.show();
				}
			});
		} else {
			SystemTray.getSystemTray().remove(trayIcon);
			Platform.exit();
		}

	}
}