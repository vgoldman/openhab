package org.openhab.binding.zwave.internal.protocol.commandclass;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.openhab.binding.zwave.internal.protocol.SecurityEncapsulatedSerialMessage;
import org.openhab.binding.zwave.internal.protocol.SerialMessage;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageClass;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageType;
import org.openhab.binding.zwave.internal.protocol.ZWaveController;
import org.openhab.binding.zwave.internal.protocol.ZWaveEndpoint;
import org.openhab.binding.zwave.internal.protocol.ZWaveEventListener;
import org.openhab.binding.zwave.internal.protocol.ZWaveNode;
import org.openhab.binding.zwave.internal.protocol.event.ZWaveEvent;
import org.openhab.binding.zwave.internal.protocol.event.ZWaveTransactionCompletedEvent;
import org.openhab.binding.zwave.internal.protocol.initialization.ZWaveNodeStageAdvancer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

/**
 * Handles the secure pairing portion and initialization of the Security command class.
 * See {@link #initialize(boolean)} for a lot of details about
 * how the secure pairing process is inherently different from the other initialization process
 *
 */
@XStreamAlias("securityCommandClassWithInit")
public class ZWaveSecurityCommandClassWithInitialization extends
		ZWaveSecurityCommandClass implements ZWaveCommandClassInitialization, ZWaveEventListener {
	private static final Logger logger = LoggerFactory.getLogger(ZWaveSecurityCommandClassWithInitialization.class);

	/**
	 * the scheme that is used prior to any keys being negotiated
	 */
	private static final byte SECURITY_SCHEME_ZERO = 0x00;

	/**
	 * Flag so we understand that the secure pairing process was completed at some point in time
	 */
	protected boolean securePairingComplete = false;

	/**
	 * Only non-null when we are including a new node
	 */
	@XStreamOmitField
	private volatile ZWaveSecureInclusionStateTracker inclusionStateTracker = null;

	/**
	 * The last {@link SerialMessage} that was given to {@link ZWaveNodeStageAdvancer}
	 * when it called {@link ZWaveSecurityCommandClass#initialize(boolean)}.   Used
	 * in cases where we need to resend the last message (transmission failure, etc)
	 */
	@XStreamOmitField
	private SerialMessage lastRequestSecurePairMessage = null;

	/**
	 * Security messages require multiple rounds of encryption so we
	 * need to allow extra time before we give up on not getting
	 * a response
	 */
	private static final int WAIT_TIME_MILLIS = 20000;

	private static final String SECURE_INCLUSION_FAILED_MESSAGE = "Secure Inclusion FAILED.";
	private static final String SECURE_INCLUSION_COMPLETE_MESSAGE = "Secure Inclusion complete";

	/**
	 * Timer that tracks how long we should wait for a response.   {@link ZWaveNodeStageAdvancer}
	 * already has a timer, but since the initialization of this class involves multiple security
	 * messages, we cannot rely on that to re-send the last message.  So, we keep our own timer
	 * to know when it's time to retry a message
	 */
	@XStreamOmitField
	private long waitForReplyTimeout = Long.MAX_VALUE;

	public ZWaveSecurityCommandClassWithInitialization(ZWaveNode node, ZWaveController controller, ZWaveEndpoint endpoint) {
		super(node, controller, endpoint);
		controller.addEventListener(this);
	}

	private boolean isSecureInclusionInProgress() {
		return inclusionStateTracker != null;
	}

	private void resetWaitForReplyTimeout() {
		waitForReplyTimeout = System.currentTimeMillis() + WAIT_TIME_MILLIS;
	}

	/**
	 * There are 2 different ways we need to transmit messages:
	 * 1) during inclusion mode, our {@link #initialize(boolean)} method will return the next message to send (handled below)
	 * 2) during normal (non-inclusion) mode, give the message to {@link ZWaveController} (handled by the superclass)
	 */
	@Override
	protected void transmitMessage(SerialMessage message) {
		if(isSecureInclusionInProgress() && message instanceof SecurityEncapsulatedSerialMessage &&
				((SecurityEncapsulatedSerialMessage) message).getSecurityPayload() != null) {
			ZWaveSecurityPayloadFrame securityPayload = ((SecurityEncapsulatedSerialMessage) message).getSecurityPayload();
			// if the message we just created is SECURITY_NETWORK_KEY_SET, then we need to change our Network Key
			// to use the real key, as the reply we will get back will be encrypted with the real Network key
			if (bytesAreEqual(securityPayload.getMessageBytes()[0], ZWaveCommandClass.CommandClass.SECURITY.getKey())
					&& bytesAreEqual(securityPayload.getMessageBytes()[1], SECURITY_NETWORK_KEY_SET)) {
				logger.info("NODE {}: Setting Network Key to real key after SECURITY_NETWORK_KEY_SET", this.getNode().getNodeId());
				setupNetworkKey(false);
			}
			// We are in inclusion mode, so give the message to the tracker so it will be picked
			// up when ZWaveNodeStageAdvancer calls our initialize method
			inclusionStateTracker.setNextRequest(message);
		} else {
			// Normal (non-inclusion mode) so give the message to the controller to be transmitted
			super.transmitMessage(message);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void handleApplicationCommandRequest(SerialMessage serialMessage, int offset, int endpoint) {
		byte command = (byte) serialMessage.getMessagePayloadByte(offset);
		if(logger.isDebugEnabled()) {
			logger.debug(String.format("NODE %s: Received Security Message 0x%02X %s ", this.getNode().getNodeId(),
					command, commandToString(command)));
		}
		traceHex("payload bytes for incoming security message", serialMessage.getMessagePayload());
		lastReceivedMessageTimestamp = System.currentTimeMillis();
		if(inclusionStateTracker != null && !inclusionStateTracker.verifyAndAdvanceState(command)) {
			// bad order, abort
			return;
		}

		switch (command) {

		case SECURITY_SCHEME_REPORT:
			// Should be received during inclusion only
			if(!wasThisNodeJustIncluded() || inclusionStateTracker == null) {
				logger.error("NODE {}: Received SECURITY_SCHEME_REPORT but we are not in inclusion mode! {}", serialMessage);
				return;
			}
			int schemes = serialMessage.getMessagePayloadByte(offset + 1);
			logger.debug("NODE {}: Received Security Scheme Report: ", this.getNode().getNodeId(), schemes);
			if (schemes == SECURITY_SCHEME_ZERO) {
				// Since we've agreed on a scheme for which to exchange our key, we now send our NetworkKey to the device
				logger.debug("NODE {}: Security scheme agreed.", this.getNode().getNodeId());
				// create the NetworkKey Packet
				SerialMessage networkKeyMessage = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
						SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler, SECURITY_MESSAGE_PRIORITY);
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				baos.write((byte) this.getNode().getNodeId());
				baos.write(18);
				baos.write((byte) getCommandClass().getKey());
				baos.write(SECURITY_NETWORK_KEY_SET);
				try {
					baos.write(realNetworkKey.getEncoded());
					networkKeyMessage.setMessagePayload(baos.toByteArray());
					// We can't set SECURITY_NETWORK_KEY_SET in inclusionStateTracker because we need to do a
					// NONCE_GET before sending.  So put this in our encrypt send queue
					// and give inclusionStateTracker/ZWaveNodeStageAdvancer the NONCE_GET
					queueMessageForEncapsulationAndTransmission(networkKeyMessage);
					if(!inclusionStateTracker.verifyAndAdvanceState(SECURITY_NETWORK_KEY_SET)) {
						return;
					}
					SerialMessage message = nonceGeneration.buildNonceGetIfNeeded();
					// Since we are in init mode, message should always != null
					if(message == null) {
						logger.error("NODE {}: "+SECURE_INCLUSION_FAILED_MESSAGE+"  In inclusion mode but buildNonceGetIfNeeded returned null, this may result in a deadlock");
					}
					inclusionStateTracker.setNextRequest(message); // Let ZWaveNodeStageAdvancer come get the NONCE_GET
				} catch (IOException e) {
					logger.error("NODE {}: IOException trying to write SECURITY_NETWORK_KEY_SET, aborted", e);
				}
			} else {
				// No common security scheme. This really shouldn't happen
				inclusionStateTracker.setErrorState("TODO: Security scheme "+schemes+" is not supported");
				logger.error("NODE {}: "+SECURE_INCLUSION_FAILED_MESSAGE+"  No common security scheme.  The device will continue as an unsecured node.  " +
						"Scheme requested was {}", this.getNode().getNodeId(), schemes);
			}
			return;

		case SECURITY_NETWORK_KEY_VERIFY:
			// Should be received during inclusion only
			if(!wasThisNodeJustIncluded() || inclusionStateTracker == null) {
				logger.error("NODE {}: Received SECURITY_NETWORK_KEY_VERIFY but we are not in inclusion mode! {}", serialMessage);
				return;
			}
			// Since we got here, it means we decrypted a packet using the key we sent in
			// the SECURITY_NETWORK_KEY_SET message and the new key is in use by both sides.
			// Next step is to send SECURITY_COMMANDS_SUPPORTED_GET
			securePairingComplete = true;
			if(SEND_SECURITY_COMMANDS_SUPPORTED_GET_ON_STARTUP) {
				logger.info("NODE {}: "+SECURE_INCLUSION_COMPLETE_MESSAGE, this.getNode().getNodeId());
			}
			SerialMessage supportedGetMessage = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
					SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler, SECURITY_MESSAGE_PRIORITY);
			byte[] payload = {
					(byte) this.getNode().getNodeId(),
					2,
					(byte) getCommandClass().getKey(),
					SECURITY_COMMANDS_SUPPORTED_GET,
			};
			supportedGetMessage.setMessagePayload(payload);
			inclusionStateTracker.verifyAndAdvanceState(SECURITY_COMMANDS_SUPPORTED_GET);
			SerialMessage nonceGetMessage = nonceGeneration.buildNonceGetIfNeeded();
			// Since we are in init mode, message should always != null
			if(nonceGetMessage == null) {
				logger.error("NODE {}: "+SECURE_INCLUSION_FAILED_MESSAGE+" In inclusion mode but buildNonceGetIfNeeded returned null, this may result in a deadlock");
			}
			inclusionStateTracker.setNextRequest(nonceGetMessage); // Let ZWaveNodeStageAdvancer come get it
			// We can't set SECURITY_COMMANDS_SUPPORTED_GET in inclusionStateTracker because we need to do a
			// NONCE_GET before sending.  So put this in our encrypt send queue
			// and give inclusionStateTracker/ZWaveNodeStageAdvancer the NONCE_GET
			queueMessageForEncapsulationAndTransmission(supportedGetMessage);
			return;

		case SECURITY_COMMANDS_SUPPORTED_REPORT:
			processSecurityCommandsSupportedReport(serialMessage, offset);
			// This can be received during device inclusion or outside of it
			if(inclusionStateTracker != null) {
				// We're done with all of our NodeStage#SECURITY_REPORT stuff, set inclusionStateTracker to null
				inclusionStateTracker = null;
			}
			return;

		case SECURITY_NONCE_GET:  		// SECURITY_NONCE_GET is handled by superclass
		case SECURITY_NONCE_REPORT:		// SECURITY_NONCE_GET is handled by superclass
			super.handleApplicationCommandRequest(serialMessage, offset, endpoint);
			return;

		case SECURITY_NETWORK_KEY_SET:			// we shouldn't get a NetworkKeySet from a node if we are the controller as we send it out to the Devices
		case SECURITY_MESSAGE_ENCAP: 			// SECURITY_MESSAGE_ENCAP should be caught and handled in {@link ApplicationCommandMessageClass}
		case SECURITY_MESSAGE_ENCAP_NONCE_GET:	// SECURITY_MESSAGE_ENCAP_NONCE_GET should be caught and handled in {@link ApplicationCommandMessageClass}
			logger.info("NODE {}: Received {} from node but we shouldn't have gotten it.", this
					.getNode().getNodeId(), commandToString(command) );
			return;
		default:
			logger.warn(String.format("NODE %s: Unsupported Command 0x%02X for command class %s (0x%02X) for message %s.",
					this.getNode().getNodeId(), command, this.getCommandClass().getLabel(),
					this.getCommandClass().getKey(), serialMessage));
		}
	}

	/**
	 * {@inheritDoc}
	 *
	 *	ZWaveNodeStageAdvancer calls us for one of the following reasons:
	 *		1. It's checking for the next message to be sent  (null indicates we're done and it can move to the next stage)
	 *		2. the ZWaveNodeStageAdvancer retry timer was triggered
	 * <p/>
	 * During node inclusion we have to exchange many message with the device to setup
	 * security encapsulation.
	 * <p/>
	 * Ideally, we would create all necessary messages the very first time this method
	 * is called and return the collection.  But that is not achievable due to the following:
	 * 1. Some messages depend on the result of previous responses.
	 * 2. In order to send a security encapsulated message, we need to send a {@link #SECURITY_NONCE_GET},
	 * wait for the {@link #SECURITY_NONCE_REPORT} and use that data to build the message.  Theoretically
	 * we could send many of these at once and get the replies, but they are valid for as little as 3
	 * seconds so they would expire before we the message that used the nonce would ever reach the device.
	 * <p/>
	 * Since we can't create all messages at once, we create a helper {@link ZWaveSecureInclusionStateTracker}
	 * which keeps track of where we are at in the flow and hold the next message to be sent.  For security
	 * reasons, it's also critical to track that the steps are executing in the proper order.
	 * <p/>
	 * Adding even more complexity, this method is frequently invoked by {@link ZWaveController.ZWaveInputThread} which means
	 * that as long as the thread is here, we will not process any incoming messages such as {@link #SECURITY_NONCE_REPORT}.
	 * To avoid blocking the thread, we return an empty collection to indicate that we are still waiting for a response message.
	 * <p/>
	 * This method is nasty but I've already spent hours trying to refactor it into readable code but have obviously failed.
	 * <p/>
	 * This code is only executed during secure inclusion.
	 *
	 * @return One or more {@link SerialMessage} to be sent OR a zero length collection if we are still waiting for a response OR
	 * null if the secure pairing process has completed or failed
	 *
	 * @see {@link ZWaveNodeStageAdvancer}
	 */
	@Override
	public Collection<SerialMessage> initialize(boolean firstIteration) {
		// ZWaveNodeStageAdvancer calls us for one of the following reasons:
		// 1. It's checking for the next message to be sent  (null indicates we're done and it can move to the next stage)
		// 2. the ZWaveNodeStageAdvancer retry timer was triggered
		boolean wasThisNodeJustIncluded = wasThisNodeJustIncluded();
		if(firstIteration) {
			resetWaitForReplyTimeout();
		}
		checkInit();
		logger.debug("NODE {}: call from NodeAdvancer initialize, firstIteration={}, wasThisNodeJustIncluded={}, keyVerifyReceived={}, "
				+ "lastReceivedMessage={}ms ago, lastSentMessage={}ms ago",
				this.getNode().getNodeId(), firstIteration, wasThisNodeJustIncluded, securePairingComplete,
				(System.currentTimeMillis() - lastReceivedMessageTimestamp), (System.currentTimeMillis() - lastSentMessageTimestamp));

		if (wasThisNodeJustIncluded) {
			List<SerialMessage> inclusionMessageReturnList = null;
			if(firstIteration && !securePairingComplete) {
				// if we are adding this node, then send SECURITY_SCHEME_GET which will start the Network Key Exchange
				setupNetworkKey(true);
				inclusionStateTracker = new ZWaveSecureInclusionStateTracker(getNode());
				// Need to start things off by sending SECURITY_SCHEME_GET
				SerialMessage message = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
						SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler, SECURITY_MESSAGE_PRIORITY);
				byte[] payload = {
						(byte) this.getNode().getNodeId(),
						3,
						(byte) getCommandClass().getKey(),
						SECURITY_SCHEME_GET,
						0
				};
				// SchemeGet is unencrypted
				message.setMessagePayload(payload);
				inclusionMessageReturnList = Collections.singletonList(message);
			} else if(receivedSecurityCommandsSupportedReport) {
				// SECURITY_COMMANDS_SUPPORTED_REPORT is received and that is our step in the secure inclusion process
				if(!SEND_SECURITY_COMMANDS_SUPPORTED_GET_ON_STARTUP) {
					logger.error("NODE {}: "+SECURE_INCLUSION_COMPLETE_MESSAGE, getNode().getNodeId());
				}
				inclusionMessageReturnList = null; // Tell ZWaveNodeStageAdvancer to advance to the next stage
			} else { // Normal inclusion flow, get the next message or wait for a response to the current one
				SerialMessage nextMessage = inclusionStateTracker.getNextRequest();
				logger.debug("NODE {}: call from NodeAdvancer initialize, inclusion flow, get the next message or wait for a response to the current one, nextMessage={}",
						this.getNode().getNodeId(), nextMessage);
				if(nextMessage == null) { // There is an outstanding request
					if(inclusionStateTracker.getErrorState() != null) { // Check for errors
						logger.error("NODE {}: "+SECURE_INCLUSION_FAILED_MESSAGE+" at step {}: {}",
								this.getNode().getNodeId(), commandToString(inclusionStateTracker.getCurrentStep()),
								inclusionStateTracker.getErrorState());
						inclusionStateTracker = null;
						inclusionMessageReturnList = null;
					} else {
						// Check our own retry timer (see waitForReplyTimeout javadoc) to see if we need to repeat the last message
						if(System.currentTimeMillis() > waitForReplyTimeout) {
							inclusionMessageReturnList = buildRetryMessageList(wasThisNodeJustIncluded);
						} else {
							inclusionMessageReturnList = Collections.emptyList();  // Keep waiting for a response
						}
					}
				} else { // nextMessage != null: There is no outstanding request and we have another message to send
					// Send the next request
					inclusionMessageReturnList = Collections.singletonList(nextMessage);
				} // END
			} // END else  Normal inclusion flow, get the next message or wait for a response to the current one
			if(inclusionMessageReturnList != null && inclusionMessageReturnList.size() > 0) {
				resetWaitForReplyTimeout();
				lastRequestSecurePairMessage = inclusionMessageReturnList.get(0);
			}
			logger.debug("NODE {}: call from NodeAdvancer initialize, just included, handing back message={}",
					this.getNode().getNodeId(), inclusionMessageReturnList == null ? "null" : inclusionMessageReturnList);
			return inclusionMessageReturnList;
			// END wasThisNodeJustIncluded
		} else { // Our node was NOT just included
			List<SerialMessage> returnMessageList = null;
			if(!securePairingComplete) {
				logger.error("NODE {}: Invalid state! secure inclusion has not completed and we are not in inclusion mode, aborting",
						this.getNode().getNodeId());
				returnMessageList = null;

				// The node was initialized previously and we are connecting to it after an openhab restart
			} else if(firstIteration) { // request the current list of security commands as a sanity check
				if(!SEND_SECURITY_COMMANDS_SUPPORTED_GET_ON_STARTUP) {
					return null; // nothing to do
				}
				SerialMessage message = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
						SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler, SECURITY_MESSAGE_PRIORITY);
				byte[] payload = {
						(byte) this.getNode().getNodeId(),
						2,
						(byte) getCommandClass().getKey(),
						SECURITY_COMMANDS_SUPPORTED_GET,
				};
				message.setMessagePayload(payload);
				resetWaitForReplyTimeout();

				SerialMessage nonceGetMessage = nonceGeneration.buildNonceGetIfNeeded();
				// We can't return SECURITY_COMMANDS_SUPPORTED_GET because we need to do a
				// NONCE_GET before sending.  So put this in our encrypt send queue
				// and give ZWaveNodeStageAdvancer the NONCE_GET
				queueMessageForEncapsulationAndTransmission(message);
				returnMessageList = Collections.singletonList(nonceGetMessage);
			} else if(receivedSecurityCommandsSupportedReport) {
				returnMessageList = null; // Normal flow, nothing else to do, tell ZWaveNodeStageAdvancer to advance to the next stage
			} else if(System.currentTimeMillis() > waitForReplyTimeout) {
				logger.error("NODE {}: Got no response to InitialSupportedGet, aborting", this.getNode().getNodeId());
				// TODO: DB hold on to the last message and resend if the timer expires
				returnMessageList = null; // Tell ZWaveNodeStageAdvancer to advance to the next stage
			} else {
				// the request was already sent, wait for the nonce exchange and the reply to come
				returnMessageList = Collections.emptyList();
			}
			logger.debug("NODE {}: call from NodeAdvancer initialize, from xml, handing back message={}",
					this.getNode().getNodeId(), returnMessageList);
			if(returnMessageList != null && returnMessageList.size() > 0) {
				resetWaitForReplyTimeout();
				lastRequestSecurePairMessage = returnMessageList.get(0);
			}
			return returnMessageList;
		} // end if wasThisNodeJustIncluded
	}

	private List<SerialMessage> buildRetryMessageList(boolean wasThisNodeJustIncluded) {
		List<SerialMessage> timeoutMessageReturnList = null;
		if(lastReceivedMessageTimestamp > lastSentMessageTimestamp) {
			logger.warn("NODE {}: Possible bug as waitForReplyTimeout triggered but we received a message last; aborting init.  lastSentMessage={}", getNode().getNodeId(), lastSentMessageTimestamp);
			timeoutMessageReturnList = null;
		} else { // We've been waiting for a reply but haven't gotten it yet, assume communication failure and resend the last message
			if(lastRequestSecurePairMessage == null) {
				logger.warn("NODE {}: Possible bug as waitForReplyTimeout triggered but lastRequestInitMessage=null; aborting init.  lastSentMessage={}", getNode().getNodeId(), lastSentMessageTimestamp);
				timeoutMessageReturnList = null;
			} else {
				timeoutMessageReturnList = Collections.singletonList(lastRequestSecurePairMessage);
				logger.warn("NODE {}: waitForReplyTimeout triggered, handing back previous sent message",
						this.getNode().getNodeId());
				// No need to update lastRequestInitMessage since it remains the same
			}
		}
		logger.debug("NODE {}: call from NodeAdvancer initialize, waitForReplyTimeout triggered, handing back message={}",
				this.getNode().getNodeId(), timeoutMessageReturnList);
		if(timeoutMessageReturnList == null) {
			if(wasThisNodeJustIncluded) {
				logger.error("NODE {}: "+SECURE_INCLUSION_FAILED_MESSAGE+" At step {}: {}",
						this.getNode().getNodeId(), commandToString(inclusionStateTracker.getCurrentStep()),
						inclusionStateTracker.getErrorState());
				inclusionStateTracker = null;
				// TODO: DB remove the node?
			}
		} else if(timeoutMessageReturnList.size() > 0) {
			resetWaitForReplyTimeout();
		}
		logger.debug("NODE {}: call from NodeAdvancer initialize, waitForReplyTimeout, handing back message={}",
				this.getNode().getNodeId(), timeoutMessageReturnList);
		return timeoutMessageReturnList;
	}

	@Override
	public void ZWaveIncomingEvent(ZWaveEvent event) {
		if(event instanceof ZWaveTransactionCompletedEvent && event.getNodeId() == getNode().getNodeId()) {
			logger.trace("NODE {}: updating  lasSentMessageTimestamp", this.getNode().getNodeId());
			lastSentMessageTimestamp = System.currentTimeMillis();
		}
	}

	@Override
	protected void checkInit() {
		super.checkInit();
	}

	@Override
	boolean checkRealNetworkKeyLoaded() {
		if(realNetworkKey == null) {
			String errorMessage = "NODE "+this.getNode()+": Trying to perform secure operation but Network key is NOT set due to: ";
			if(keyException != null) {
				errorMessage += keyException.getMessage();
			}
			logger.error(errorMessage, keyException);
			if(inclusionStateTracker != null) {
				inclusionStateTracker.setErrorState(errorMessage);
			}
			return false;
		}
		return true;
	}

}
