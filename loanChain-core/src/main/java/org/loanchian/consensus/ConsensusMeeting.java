package org.loanchian.consensus;

import org.loanchian.account.Account;
import org.loanchian.crypto.Sha256Hash;
import org.loanchian.message.Block;
import org.loanchian.message.ConsensusMessage;

import java.util.List;
import java.util.Set;

/**
 * 共识过程，这里理解为共识会议，所有共识人一起开一个永不结束的会议
 * 会议对于所有节点都是透明的，但是只有共识节点才能发言，如果非共识节点违规发言，则有可能面临信用惩罚
 * @author ln
 *
 */
public interface ConsensusMeeting {

	/**
	 * 会议发言，向全网广播当前的想法，仅允许共识节点
	 * @param message
	 */
	void broadcastMessage(ConsensusMessage message);
	
	/**
	 * 接收来自网络的其它节点的发言，并做相应的回复
	 * @param msid
	 * @param message
	 */
	void receiveMeetingMessage(Sha256Hash msid, ConsensusMessage message);
	
	/**
	 * 获取一个已接收的共识消息，如果没有则会返回null
	 * @param msid
	 * @return ConsensusMessage
	 */
	ConsensusMessage getMeetingMessage(Sha256Hash msid);
	
	/**
	 * 消息是否接收
	 * @param msid
	 * @return boolean
	 */
	boolean messageHasReceived(Sha256Hash msid);
	
	/**
	 * 获取区块高度对应的打包人信息，只适用于新区快的验证
	 * @param periodStartTime 一轮开始的时间点，毫秒数
	 * @param timePeriod 区块时段
	 * @return ConsensusInfos
	 */
	ConsensusInfos getCurrentConsensusInfos(long periodStartTime, int timePeriod);

	/**
	 * 打包信息，轮到我打包时，根据共识会议，获取我的打包信息
	 * @return MiningInfos
	 */
	MiningInfos getMineMiningInfos();
	
	/**
	 * 设置运行账户
	 * @param account 
	 */
	void setAccount(Account account);
	
	/**
	 * 获取当前正在共识的账户
	 * @return Account 
	 */
	Account getAccount();
	
	/**
	 * 获取本轮共识的开始时间点，单位（秒）
	 * @return long
	 */
	long getPeriodStartTime();
	
	/**
	 * 获取传入的共识轮和上一轮超时的账号
	 * @return Set<TimeoutConsensusViolation>
	 */
	Set<TimeoutConsensusViolation> getTimeoutList();
	
	/**
	 * 获取某论的共识快照，从最新的内存映射倒推
	 * TODO 可以考虑做一个内存映射，每次分析计算量太大 ？
	 * @param periodStartTime
	 * @return List<ConsensusAccount>
	 */
	List<ConsensusAccount> analysisConsensusSnapshots(long periodStartTime);

	/**
	 * 获取以startPoint开始的会议详情
	 * @return MeetingItem
	 */
	MeetingItem getMeetingItem(long startPoint);
	
	/**
	 * 获取当前会议参与人数
	 * @return int
	 */
	int getCurrentMeetingPeriodCount();
	
	/**
	 * 异步启动
	 */
	void startSyn();
	
	/**
	 * 停止服务
	 */
	void stop();
	
	/**
	 * 从下一轮开始共识
	 * @param block 从该块开始
	 */
	void startConsensusOnNextRound(Block block);
	
	/**
	 * 从下一轮开始停止共识
	 * @param block 从该块开始
	 */
	void stopConsensusOnNextRound(Block block);
	
	/**
	 * 共识会议是否进行中，所有的节点都会参加会议，有权限的（共识节点）才会发言
	 * 所以外部接受新块，必须保证顺利加入会议，否则接收新块会出错
	 * 当调用此方法时，会阻塞，直到meetingStatus = 2 ，也就是初始化完成
	 */
	boolean waitMeeting();
	
	/**
	 * 等待参与会议，即申请了共识，等待打包
	 * 申请共识时，调用此方法，可知道是否成功进入到了共识模式
	 * 阻塞的方法，知道成功共识或者超时
	 */
	boolean waitMining();
	
	/**
	 * 重置当前轮共识会议，置为最新区块的状态
	 * 一般发生在处理分叉链成功之后，当前最新区块发生了变化，相应的会议也会发生变化
	 * 如果我在当前轮共识中，那么需要立即停止，并重新检测，重置之后的会议，如果错过了，那么则本轮不打包
	 * @return boolean
	 */
	boolean resetCurrentMeetingItem();
}
