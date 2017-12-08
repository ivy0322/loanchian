package org.loanchian.wallet.controllers;

import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import javafx.scene.text.Font;
import javafx.stage.Stage;
import org.loanchian.SpringContextUtils;
import org.loanchian.account.Account;
import org.loanchian.account.Address;
import org.loanchian.consensus.ConsensusMeeting;
import org.loanchian.core.DataSynchronizeHandler;
import org.loanchian.core.Definition;
import org.loanchian.core.Peer;
import org.loanchian.core.TimeService;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.kit.LoanchainInstance;
import org.loanchian.kits.AccountKit;
import org.loanchian.kits.AppKit;
import org.loanchian.kits.PeerKit;
import org.loanchian.listener.BlockChangedListener;
import org.loanchian.listener.ConnectionChangedListener;
import org.loanchian.listener.NoticeListener;
import org.loanchian.listener.TransactionListener;
import org.loanchian.store.TransactionStore;
import org.loanchian.utils.DateUtil;
import org.loanchian.wallet.listener.AccountInfoListener;
import org.loanchian.wallet.listener.StartupListener;
import org.loanchian.wallet.utils.Callback;
import org.loanchian.wallet.utils.DailogUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.*;
import java.awt.TrayIcon.MessageType;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 首页控制器
 * @author ln
 *
 */
public class MainController {
	
	private static final Logger log = LoggerFactory.getLogger(MainController.class);
	
	public Label nowNetTimeId;					//当前网络时间
	public Label localNewestHeightId;			//本地最新高度
	public Label netNewestHeightId;				//网络最新高度
	public Label blockHeightSeparator;			//本地最新高度与网络最新高度分隔符
	public Label networkInfosNumId;				//网络连接节点信息
	public DecorationController decorationController;

	//导航按钮
	public Button accountInfoId;			//账户信息
	public Button sendAmountId;				//转账
	public Button transactionRecordId;		//交易记录
	public Button consensusRecordId;		//共识节点列表
	public Button sellerRecordId;			//商家列表
	public Button applicationListId;		//应用列表
	public Button systemSettingsId;       //系统设置
	
	public ImageView netInfoImageViewId;	//网络信息
	public ImageView blockInfoImageViewtId;	//区块信息
	public ImageView nowNetTimeImageViewId;	//网络时间
	
	public StackPane contentId;				//子页面内容控件
	private List<Button> buttons = new ArrayList<Button>();
	private Map<String, Node> pageMaps = new HashMap<String, Node>();	//页面列表
	private Map<String, SubPageController> subPageControllerMaps = new HashMap<String, SubPageController>();	//页面控制器
	private String currentPageId;			//当前显示的页面
	private Stage stage;
	Image imageDecline;
	
	
	/**
	 *  FXMLLoader 调用的初始化
	 */
    public void initialize() {
    	
    	Font font = Font.font("宋体", 14);

    	Tooltip netInfoTooltip = new Tooltip("节点信息");
    	netInfoTooltip.setFont(font);
    	Tooltip.install(netInfoImageViewId, netInfoTooltip);
    	
    	Tooltip nowNetTimeTooltip = new Tooltip("网络时间");
    	nowNetTimeTooltip.setFont(font);
    	Tooltip.install(nowNetTimeImageViewId.getParent(), nowNetTimeTooltip);

    	Tooltip blockInfoTooltip = new Tooltip("区块信息");
    	blockInfoTooltip.setFont(font);
    	Tooltip.install(blockInfoImageViewtId, blockInfoTooltip);
    	
    	Tooltip localTooltip = new Tooltip("本地最新高度");
    	localTooltip.setFont(font);
    	localNewestHeightId.setTooltip(localTooltip);
    	
    	Tooltip netTooltip = new Tooltip("网络最新高度");
    	netTooltip.setFont(font);
    	netNewestHeightId.setTooltip(netTooltip);
    	
    	addImageToButton(accountInfoId,"accountInfo");
    	addImageToButton(sendAmountId,"sendAmount");
    	addImageToButton(transactionRecordId,"transactionRecord");
    	addImageToButton(consensusRecordId,"consensusRecord");
    	addImageToButton(sellerRecordId,"sellerRecord");
    	addImageToButton(applicationListId, "antifake");
    	addImageToButton(systemSettingsId, "settings");
    	
		buttons.add(accountInfoId);
		buttons.add(sendAmountId);
		buttons.add(transactionRecordId);
		buttons.add(consensusRecordId);
		buttons.add(sellerRecordId);
		buttons.add(applicationListId);
    	buttons.add(systemSettingsId);
    	
		EventHandler<ActionEvent> buttonEventHandler = getPageEventHandler();
		for (Button button : buttons) {
			button.setOnAction(buttonEventHandler);
		}
    }

	private void addImageToButton(Button button,String name) {
		imageDecline = new Image(getClass().getResourceAsStream("/images/"+name+"_icon.png")); 
		button.setGraphic(new ImageView(imageDecline));
    	button.setGraphicTextGap(10);
	}

    /**
     * 核心启动完成之后调用的初始化
     * @param startupListener 
     */
	public void init(StartupListener startupListener) {

    	startupOnChange(startupListener, "初始化网络时间", 3);
		//界面时间
    	startShowTime();
    	
    	startupOnChange(startupListener, "初始化ui", 3);
    	initPages();
    	
    	startupOnChange(startupListener, "初始化页面数据", 3);
    	initDatas(startupListener);
    	
    	startupOnChange(startupListener, "初始化监听器", 3);
    	//初始化监听器
    	initListeners();
    	//加载完成
    	startupListener.onComplete();
    	
    	//刷新当前显示页面的数据
    	refreshCurrentPageData();
    	
    	checkConsensusStatus();
	}

	//检查当前共识状态，如果是在共识队列中，则要求输入密码
	private void checkConsensusStatus() {
		new Thread() {
			@Override
			public void run() {
				try {
					Thread.sleep(3000l);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				
				final AccountKit accountKit = SpringContextUtils.getBean(AccountKit.class);
				DataSynchronizeHandler dataSynchronizeHandler = SpringContextUtils.getBean(DataSynchronizeHandler.class);
				
				while(true) {
					
					if(dataSynchronizeHandler.hasComplete()) {
						if(accountKit.checkConsensusing(null) && accountKit.isWalletEncrypted()) {
							//解密账户
							URL location = getClass().getResource("/resources/template/decryptWallet.fxml");
							final FXMLLoader loader = new FXMLLoader(location);
							final AccountKit accountKitTemp = accountKit;
							Platform.runLater(new Runnable() {
							    @Override
							    public void run() {
									DailogUtil.showDailog(loader, "输入钱包密码进行共识", new Callback() {
										@Override
										public void ok(Object param) {
											if(!accountKit.accountIsEncrypted(Definition.TX_VERIFY_TR)) {
												try {
													ConsensusMeeting consensusMeeting = SpringContextUtils.getBean(ConsensusMeeting.class);
													consensusMeeting.waitMining();
												} finally {
													accountKitTemp.resetKeys();
												}
											}
										}
									});
							    }
							});
						}
						break;
					} else {
						try {
							Thread.sleep(1000l);
						} catch (InterruptedException e) {
							e.printStackTrace();
						}
					}
				}
			}
		}.start();
	}

	/*
	 * 刷新当前页面显示的数据
	 */
	private void refreshCurrentPageData() {
		Thread t = new Thread() {
			public void run() {
				while(true) {
					SubPageController controller = subPageControllerMaps.get(currentPageId);
					
					if(controller != null && controller.refreshData()) {
						Platform.runLater(new Runnable() {
						    @Override
						    public void run() {
						    	controller.initDatas();
						    }
						});
					}
					try {
						Thread.sleep(1000l);
					} catch (InterruptedException e) {
					}
				}
			}
		};
		t.setName("refresh current page data service");
		t.start();
	}

	/*
	 * 获取页面切换事件
	 */
	private EventHandler<ActionEvent> getPageEventHandler() {
		EventHandler<ActionEvent> buttonEventHandler = new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				Button button = (Button) event.getSource();
				if(button == null) {
					return;
				}
				initButtonbg();
				button.setStyle("-fx-background-image:url(\"/images/button_bgHL.png\")");
				String id = button.getId();
				
				//触发页面显示隐藏事件
				for (Entry<String, SubPageController> entry : subPageControllerMaps.entrySet()) {
					String pageId = entry.getKey();
					SubPageController pageController = entry.getValue();
					//隐藏上个页面
					if(pageId.equals(currentPageId)) {
						pageController.onHide();
					} else if(pageId.equals(id)) {
						
						pageController.initDatas();
						
						pageController.onShow();
					}
				}
				showPage(id);
			}
		};
		return buttonEventHandler;
	}
	
	protected void initButtonbg() {
		for (Button button : buttons) {
			button.setStyle("-fx-background-image:null");
		}
	}

	/*
	 * 初始化各个页面的数据
	 */
	private void initDatas(StartupListener startupListener) {
		int completionRate = (100 - startupListener.getCompletionRate()) / 4;//subPageControllers.size();
		for (SubPageController controller : subPageControllerMaps.values()) {
			if(!controller.startupInit()) {
				continue;
			}
			
			String tip = null;
			if(controller instanceof AccountInfoController) {
				//账户信息加载完成之后，设置主界面的余额和地址信息
				AccountInfoController accountInfoController = (AccountInfoController) controller;
				accountInfoController.setAccountInfoListener(new AccountInfoListener() {
					@Override
					public void onLoad(Account account) {
						//设置地址
						final Address address = account.getAddress();
						final String addressBase58 = address.getBase58();
						Platform.runLater(new Runnable() {
						    @Override
						    public void run() {
						    	decorationController.setAccountAddressId(addressBase58);
						    	decorationController.setTipText(addressBase58);
								//设置余额
						    	decorationController.setBalanceId(address.getBalance().add(address.getUnconfirmedBalance()).toText());
						    }
						});
					}
				});
				tip = "初始化账户信息";
			} else if(controller instanceof TransactionRecordController) {
				tip = "初始化交易记录";
			} else if(controller instanceof AccountInfoController) {
				tip = "初始化共识信息";
			} else if(controller instanceof AccountInfoController) {
				tip = "初始化商家信息";
			}else if(controller instanceof SystemSettingsController) {
				tip = "初始化系统信息";
			}
			if(tip != null) {
				startupOnChange(startupListener, tip, completionRate);
			}
			controller.initDatas();
		}
	}
	
	/*
	 * 启动变化
	 */
	private void startupOnChange(StartupListener startupListener, String tip, int completionRate) {
    	startupListener.setCompletionRate(startupListener.getCompletionRate() + completionRate);
    	startupListener.onChange(tip);
	}

	/*
	 * 初始化各个界面
	 */
	private void initPages() {

		for (Button button : buttons) {
			String id = button.getId();
			pageMaps.put(id, getPage(id));
		}
		buttons.get(0).setStyle("-fx-background-image:url(\"/images/button_bgHL.png\")");
		//显示第一个子页面
		if(buttons.size() > 0) {
			showPage(buttons.get(0).getId());
		}
	}

	private long localHeight,netHeight;
	/*
	 * 初始化数据变化监听器
	 */
	private void initListeners() {
		//注入区块变化监听器
    	LoanchainInstance instance = LoanchainInstance.getInstance();
    	AppKit appKit = instance.getAppKit();
    	DataSynchronizeHandler dataSynchronizeHandler = SpringContextUtils.getBean(DataSynchronizeHandler.class);
    	appKit.addBlockChangedListener(new BlockChangedListener() {
			@Override
			public void onChanged(final long localNewestHeight, final long netNewestHeight, final Sha256Hash localNewestHash,
					final Sha256Hash netNewestHash) {
				Platform.runLater(new Runnable() {
				    @Override
				    public void run() {
				    	if(localNewestHeight != -1l) {
					    	localNewestHeightId.setText(String.valueOf(localNewestHeight));
					    	localNewestHeightId.getTooltip().setText(String.format("本地最新高度 %d", localNewestHeight));
					    	
					    	localHeight = localNewestHeight;
				    	}
				    	if(netNewestHeight != -1l) {
				    		if(!blockHeightSeparator.isVisible()) {
				    			blockHeightSeparator.setVisible(true);
				    			netNewestHeightId.setVisible(true);
				    		}
					    	netNewestHeightId.setText(String.valueOf(netNewestHeight));
					    	netNewestHeightId.getTooltip().setText(String.format("网络最新高度 %d", netNewestHeight));
					    	
					    	netHeight = netNewestHeight;
				    	}
				    	if(localHeight > netHeight) {
				    		netNewestHeightId.setText(String.valueOf(localHeight));
					    	netNewestHeightId.getTooltip().setText(String.format("网络最新高度 %d", localHeight));
				    	}
				    }
				});
			}
		});
    	
    	final PeerKit peerKit = instance.getPeerKit();
    	//网络变化监听器
    	appKit.addConnectionChangedListener(new ConnectionChangedListener() {
			@Override
			public void onChanged(final int inCount, final int outCount,final int superCount, final CopyOnWriteArrayList<Peer> inPeers,
					final CopyOnWriteArrayList<Peer> outPeers,final CopyOnWriteArrayList<Peer> superPeers) {
				new Thread() {
					public void run() {
						try {
							Thread.sleep(1000l);
						} catch (InterruptedException e) {
							e.printStackTrace();
						}
						Platform.runLater(new Runnable() {
							@Override
							public void run() {
								int[] counts = peerKit.getAvailablePeersCounts();
								int inPeerCount = counts[0];
								int outPeerCount = counts[1];
								int superPeerCount = counts[2];
								networkInfosNumId.setText(String.valueOf(inPeerCount + outPeerCount + superPeerCount));
								networkInfosNumId.getTooltip().setText(String.format("主动连接：%d\r\n被动连接：%d", outPeerCount+superPeerCount, inPeerCount));
							}
						});
					};
				}.start();
			}
		});
    	
    	//注入新交易监听器
    	appKit.getAccountKit().setTransactionListener(new TransactionListener() {
    		@Override
    		public void newTransaction(TransactionStore tx) {
    			for (SubPageController controller : subPageControllerMaps.values()) {
    				if(controller instanceof AccountInfoController
    						|| controller instanceof TransactionRecordController) {
        				controller.initDatas();
    				}
    			}
    		}
		});
    	
		//通知器
    	instance.getAccountKit().setNoticeListener(new NoticeListener() {
			@Override
			public void onNotice(String title, String message) {
				onNotice(NOTICE_TYPE_NONE, title, message);
			}
			@Override
			public void onNotice(int type, String title, String message) {
				//如果是同步过程中，则不提示
				boolean blockNewest = appKit.getNetwork().blockIsNewestStatus();
				if(!blockNewest || !dataSynchronizeHandler.hasComplete()) {
					return;
				}
				
				TrayIcon[] trayIcons = SystemTray.getSystemTray().getTrayIcons();
    			if(trayIcons != null && trayIcons.length > 0) {
    				MessageType messageType;
    				if(type == NOTICE_TYPE_ERROR) {
    					messageType = MessageType.ERROR;
    				} else if(type == NOTICE_TYPE_WARNING) {
    					messageType = MessageType.WARNING;
    				} else if(type == NOTICE_TYPE_NONE) {
    					messageType = MessageType.NONE;
    				} else {
    					messageType = MessageType.INFO;
    				}
    				trayIcons[0].displayMessage(title, message, messageType);
    			}
			}
		});
	}
	
	/**
	 * 显示子页面
	 * @param id
	 */
	private void showPage(final String id) {
		Platform.runLater(new Runnable() {
		    @Override
		    public void run() {
				Node page = pageMaps.get(id);
				
				if(page == null) {
					page = getPage(id);
					if(page == null) {
						return;
					}
					pageMaps.put(id, page);
				}
				contentId.getChildren().clear();
				contentId.getChildren().add(page);
				
				currentPageId = id;
		    }
		});
	}

    /**
     * 根据ID获取中间内容页面* 
     * @param id
     * @return
     */
	private Node getPage(String id) {
		
		String fxml = null;
		
		switch (id) {
		case "accountInfoId":
			//点击账户信息按钮
			fxml = "/resources/template/accountInfo.fxml";
			break;
		case "sendAmountId":
			//点击转账按钮
			fxml = "/resources/template/sendAmount.fxml";
			break;
		case "transactionRecordId":
			//点击交易记录按钮
			fxml = "/resources/template/transactionRecord.fxml";
			break;
		case "consensusRecordId":
			//点击共识列表按钮
			fxml = "/resources/template/consensus.fxml";
			break;

		case "systemSettingsId":
			//点击系统设置按钮
			fxml = "/resources/template/systemSettings.fxml";
			break;
		default:
			break;
		}
		
		if(fxml != null) {
			try {
		        FXMLLoader loader = new FXMLLoader(getClass().getResource(fxml));
				Pane page = loader.load();
				SubPageController subPageController = loader.getController();
				if(subPageController != null) {
					subPageControllerMaps.put(id, subPageController);
				}
				return page;
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			}
		}
		return null;
	}

	/*
	 * 开始显示时间，这里显示的是网络时间，并不是本地时间
	 */
	private void startShowTime() {
		new Thread(){
    		public void run() {
    			while(true) {
    				try {
    					Platform.runLater(new Runnable() {
    					    @Override
    					    public void run() {
    					    	nowNetTimeId.setText(DateUtil.convertDate(new Date(TimeService.currentTimeMillis())));
    					    }
    					});
    					Thread.sleep(1000l);
    				} catch (Exception e) {
    					e.printStackTrace();
    				}
    			}
    		};
    	}.start();
	}
	public DecorationController getDecorationController() {
		return decorationController;
	}

	public void setDecorationController(DecorationController decorationController) {
		this.decorationController = decorationController;
	}
    public void setStage(Stage stage) {
		this.stage = stage;
	}
    public Stage getStage() {
		return stage;
	}
}
