/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.plugwise.internal;

import static org.quartz.JobBuilder.newJob;
import static org.quartz.SimpleScheduleBuilder.simpleSchedule;
import static org.quartz.TriggerBuilder.newTrigger;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.TooManyListenersException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.openhab.binding.plugwise.PlugwiseCommandType;
import org.openhab.binding.plugwise.protocol.AcknowledgeMessage;
import org.openhab.binding.plugwise.protocol.CalibrationResponseMessage;
import org.openhab.binding.plugwise.protocol.ClockGetResponseMessage;
import org.openhab.binding.plugwise.protocol.InformationResponseMessage;
import org.openhab.binding.plugwise.protocol.InitialiseRequestMessage;
import org.openhab.binding.plugwise.protocol.InitialiseResponseMessage;
import org.openhab.binding.plugwise.protocol.Message;
import org.openhab.binding.plugwise.protocol.MessageType;
import org.openhab.binding.plugwise.protocol.NodeAvailableMessage;
import org.openhab.binding.plugwise.protocol.NodeAvailableResponseMessage;
import org.openhab.binding.plugwise.protocol.PowerBufferResponseMessage;
import org.openhab.binding.plugwise.protocol.PowerInformationResponseMessage;
import org.openhab.binding.plugwise.protocol.RealTimeClockGetResponseMessage;
import org.openhab.binding.plugwise.protocol.RoleCallResponseMessage;
import org.quartz.Job;
import org.quartz.JobDataMap;
import org.quartz.JobDetail;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.JobListener;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.Trigger;
import org.quartz.impl.StdSchedulerFactory;
import org.quartz.impl.matchers.KeyMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gnu.io.CommPortIdentifier;
import gnu.io.PortInUseException;
import gnu.io.SerialPort;
import gnu.io.SerialPortEvent;
import gnu.io.SerialPortEventListener;
import gnu.io.UnsupportedCommOperationException;

/**
 * This class represents a Plugwise Stick that is connected to a serial port on the host.
 * This class borrows heavily from the Serial binding for the serial port communication
 *
 * @author Karel Goderis
 * @since 1.1.0
 */
public class Stick extends PlugwiseDevice implements SerialPortEventListener {

    private static final Logger logger = LoggerFactory.getLogger(Stick.class);

    /** Plugwise protocol header code (hex) */
    private final static String PROTOCOL_HEADER = "\u0005\u0005\u0003\u0003";

    /** Plugwise protocol trailer code (hex) */
    private final static String PROTOCOL_TRAILER = "\r\n";

    /** counter to track Quartz Jobs */
    private static int counter = 0;

    // Serial communication fields
    private String port;
    private CommPortIdentifier portId;
    private SerialPort serialPort;
    private WritableByteChannel outputChannel;
    private ByteBuffer readBuffer;

    // Queue fields
    protected static int maxBufferSize = 1024;
    protected final ReentrantLock queueLock = new ReentrantLock();
    protected final ReentrantLock receiveLock = new ReentrantLock();
    protected ArrayBlockingQueue<Message> sendQueue = new ArrayBlockingQueue<Message>(maxBufferSize, true);
    protected ArrayBlockingQueue<Message> sentQueue = new ArrayBlockingQueue<Message>(maxBufferSize, true);
    protected ArrayBlockingQueue<Message> receivedQueue = new ArrayBlockingQueue<Message>(maxBufferSize, true);

    // Stick fields
    private boolean initialised = false;
    protected List<PlugwiseDevice> plugwiseDeviceCache = Collections.synchronizedList(new ArrayList<PlugwiseDevice>());
    private PlugwiseBinding binding;
    /** default interval for sending messages on the ZigBee network */
    private int interval = 50;
    /** default maximum number of attempts to send a message */
    private int maxRetries = 1;

    public Stick(String port, PlugwiseBinding binding) {
        super("", PlugwiseDevice.DeviceType.Stick, "stick");
        this.port = port;
        this.binding = binding;
        plugwiseDeviceCache.add(this);
        try {
            initialize();
        } catch (PlugwiseInitializationException e) {
            logger.error("Failed to initialize Plugwise stick: {}", e.getLocalizedMessage());
            initialised = false;
        }
    }

    protected static Comparator<PlugwiseDevice> plugComparator = new Comparator<PlugwiseDevice>() {
        @Override
        public int compare(PlugwiseDevice u1, PlugwiseDevice u2) {
            return u1.getMAC().compareTo(u2.getMAC());
        }
    };

    protected static Comparator<PlugwiseDevice> friendlyPlugComparator = new Comparator<PlugwiseDevice>() {
        @Override
        public int compare(PlugwiseDevice u1, PlugwiseDevice u2) {
            return u1.getFriendlyName().compareTo(u2.getFriendlyName());
        }
    };

    protected PlugwiseDevice getDevice(String id) {
        PlugwiseDevice someDevice = getDeviceByMAC(id);
        if (someDevice == null) {
            return getDeviceByName(id);
        } else {
            return someDevice;
        }
    }

    protected PlugwiseDevice getDeviceByMAC(String MAC) {

        PlugwiseDevice queryDevice = new PlugwiseDevice(MAC, null, "");
        Collections.sort(plugwiseDeviceCache, plugComparator);
        int index = Collections.binarySearch(plugwiseDeviceCache, queryDevice, plugComparator);
        if (index >= 0) {
            return plugwiseDeviceCache.get(index);
        } else {
            return null;
        }
    }

    protected PlugwiseDevice getDeviceByName(String name) {

        PlugwiseDevice queryDevice = new PlugwiseDevice(null, null, name);
        Collections.sort(plugwiseDeviceCache, friendlyPlugComparator);
        int index = Collections.binarySearch(plugwiseDeviceCache, queryDevice, friendlyPlugComparator);
        if (index >= 0) {
            return plugwiseDeviceCache.get(index);
        } else {
            return null;
        }
    }

    public String getPort() {
        return port;
    }

    public void setInterval(int interval) {
        this.interval = interval;
    }

    public void setRetries(int retries) {
        this.maxRetries = retries;
    }

    public boolean isInitialised() {
        return initialised;
    }

    /**
     * Initialize this device and open the serial port
     *
     * @throws PlugwiseInitializationException if port can not be opened
     */
    @SuppressWarnings("rawtypes")
    private void initialize() throws PlugwiseInitializationException {

        // Flush the deviceCache
        if (this.plugwiseDeviceCache != null) {
            plugwiseDeviceCache = Collections.synchronizedList(new ArrayList<PlugwiseDevice>());
        }

        // parse ports and if the default port is found, initialized the reader
        Enumeration portList = CommPortIdentifier.getPortIdentifiers();
        while (portList.hasMoreElements()) {
            CommPortIdentifier id = (CommPortIdentifier) portList.nextElement();
            if (id.getPortType() == CommPortIdentifier.PORT_SERIAL) {
                if (id.getName().equals(port)) {
                    logger.debug("Serial port '{}' has been found.", port);
                    portId = id;
                }
            }
        }
        if (portId != null) {
            // initialize serial port
            try {
                serialPort = portId.open("openHAB", 2000);
            } catch (PortInUseException e) {
                throw new PlugwiseInitializationException(e);
            }

            try {
                serialPort.addEventListener(this);
            } catch (TooManyListenersException e) {
                throw new PlugwiseInitializationException(e);
            }

            // activate the DATA_AVAILABLE notifier
            serialPort.notifyOnDataAvailable(true);

            try {
                // set port parameters
                serialPort.setSerialPortParams(115200, SerialPort.DATABITS_8, SerialPort.STOPBITS_1,
                        SerialPort.PARITY_NONE);
            } catch (UnsupportedCommOperationException e) {
                throw new PlugwiseInitializationException(e);
            }

            try {
                // get the output stream
                outputChannel = Channels.newChannel(serialPort.getOutputStream());
            } catch (IOException e) {
                throw new PlugwiseInitializationException(e);
            }
        } else {
            StringBuilder sb = new StringBuilder();
            portList = CommPortIdentifier.getPortIdentifiers();
            while (portList.hasMoreElements()) {
                CommPortIdentifier id = (CommPortIdentifier) portList.nextElement();
                if (id.getPortType() == CommPortIdentifier.PORT_SERIAL) {
                    sb.append(id.getName() + "\n");
                }
            }
            throw new PlugwiseInitializationException(
                    "Serial port '" + port + "' could not be found. Available ports are:\n" + sb);
        }

        // set up the Quartz jobs

        Scheduler sched = null;
        try {
            sched = StdSchedulerFactory.getDefaultScheduler();
        } catch (SchedulerException e) {
            logger.error("Error getting a reference to the Quartz Scheduler");
        }

        JobDataMap map = new JobDataMap();
        map.put("Stick", this);

        JobDetail job = newJob(SendJob.class).withIdentity("Send-0", "Plugwise").usingJobData(map).build();

        Trigger trigger = newTrigger().withIdentity("Send-0", "Plugwise").startNow().build();

        try {
            sched.getListenerManager().addJobListener(new SendJobListener("JobListener-" + job.getKey().toString()),
                    KeyMatcher.keyEquals(job.getKey()));
        } catch (SchedulerException e1) {
            logger.error("An exception occured while attaching a Quartz Send Job Listener");
        }

        try {
            sched.scheduleJob(job, trigger);
        } catch (SchedulerException e) {
            logger.error("Error scheduling a job with the Quartz Scheduler");
        }

        map = new JobDataMap();
        map.put("Stick", this);

        job = newJob(ProcessMessageJob.class).withIdentity("ProcessMessage", "Plugwise").usingJobData(map).build();

        trigger = newTrigger().withIdentity("ProcessMessage", "Plugwise").startNow()
                .withSchedule(simpleSchedule().repeatForever().withIntervalInMilliseconds(50)).build();

        try {
            sched.scheduleJob(job, trigger);
        } catch (SchedulerException e) {
            logger.error("Error scheduling a job with the Quartz Scheduler");
        }

        // initialise the Stick
        initialised = true;
        InitialiseRequestMessage message = new InitialiseRequestMessage();
        sendMessage(message);

    }

    /**
     * Close this serial device associated with the Stick
     */
    public void close() {
        serialPort.removeEventListener();
        try {
            IOUtils.closeQuietly(serialPort.getInputStream());
            IOUtils.closeQuietly(serialPort.getOutputStream());
            serialPort.close();
        } catch (IOException e) {
            logger.error("An exception occurred while closing the serial port {} ({})", serialPort, e.getMessage());
        }

        initialised = false;

    }

    @Override
    public void serialEvent(SerialPortEvent event) {
        switch (event.getEventType()) {
            case SerialPortEvent.BI:
            case SerialPortEvent.OE:
            case SerialPortEvent.FE:
            case SerialPortEvent.PE:
            case SerialPortEvent.CD:
            case SerialPortEvent.CTS:
            case SerialPortEvent.DSR:
            case SerialPortEvent.RI:
            case SerialPortEvent.OUTPUT_BUFFER_EMPTY:
                break;
            case SerialPortEvent.DATA_AVAILABLE:
                // we get here if data has been received
                boolean newlineFound = false;
                if (readBuffer == null) {
                    readBuffer = ByteBuffer.allocate(maxBufferSize);
                }
                try {
                    // read data from serial device
                    while (serialPort.getInputStream().available() > 0) {
                        int aByte = serialPort.getInputStream().read();
                        if ((aByte) == 13) {
                            readBuffer.put((byte) aByte);
                            int cr = serialPort.getInputStream().read();
                            readBuffer.put((byte) cr);
                            newlineFound = true;
                            break;
                        }
                        // Plugwise sends ASCII data, but for some unknown reason we sometimes get data with unsigned
                        // byte value >127
                        // which in itself is very strange. We filter these out for the time being
                        if (aByte < 128) {
                            readBuffer.put((byte) aByte);
                        }
                    }

                    // process data
                    if (readBuffer.position() != 0 && newlineFound == true) {
                        readBuffer.flip();
                        parseAndQueue(readBuffer);
                        readBuffer = null;
                    }
                } catch (IOException e) {
                    logger.debug("Error receiving data on serial port {}: {}", port, e.getMessage());
                }
                break;
        }
    }

    public void sendMessage(Message message) {
        if (message != null && isInitialised()) {
            try {
                logger.debug("Adding to sendQueue: {}", message);
                sendQueue.put(message);
            } catch (InterruptedException e) {
                logger.error("Interrupted while adding to sendQueue: {}", message);
            }
        }
    }

    @Override
    public boolean postUpdate(String MAC, PlugwiseCommandType type, Object value) {
        if (MAC != null && type != null && value != null) {
            binding.postUpdate(MAC, type, value);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Parse a buffer into a Message and put it in the appropriate queue for further processing
     *
     * @param readBuffer - the string to parse
     */
    private void parseAndQueue(ByteBuffer readBuffer) {
        if (readBuffer != null) {

            Pattern RESPONSE_PATTERN = Pattern.compile("(.{4})(\\w{4})(\\w{4})(\\w*?)(\\w{4})");

            String response = new String(readBuffer.array(), 0, readBuffer.limit());
            response = StringUtils.chomp(response);

            Matcher matcher = RESPONSE_PATTERN.matcher(response);

            if (matcher.matches()) {

                String protocolHeader = matcher.group(1);
                String command = matcher.group(2);
                String sequence = matcher.group(3);
                String payload = matcher.group(4);
                String CRC = matcher.group(5);

                if (protocolHeader.equals(PROTOCOL_HEADER)) {
                    String calculatedCRC = getCRCFromString(command + sequence + payload);
                    if (calculatedCRC.equals(CRC)) {

                        logger.debug("Received message: command:{} sequence:{} payload:{}",
                                MessageType.forValue(Integer.parseInt(command, 16)), Integer.parseInt(sequence, 16),
                                payload);

                        Message theMessage = null;

                        switch (MessageType.forValue(Integer.parseInt(command, 16))) {
                            case ACKNOWLEDGEMENT:
                                theMessage = new AcknowledgeMessage(Integer.parseInt(sequence, 16), payload);
                                break;
                            case NODE_AVAILABLE:
                                theMessage = new NodeAvailableMessage(Integer.parseInt(sequence, 16), payload);
                                break;
                            case INITIALISE_RESPONSE:
                                theMessage = new InitialiseResponseMessage(Integer.parseInt(sequence, 16), payload);
                                break;
                            case DEVICE_ROLECALL_RESPONSE:
                                theMessage = new RoleCallResponseMessage(Integer.parseInt(sequence, 16), payload);
                                break;
                            case DEVICE_CALIBRATION_RESPONSE:
                                theMessage = new CalibrationResponseMessage(Integer.parseInt(sequence, 16), payload);
                                break;
                            case DEVICE_INFORMATION_RESPONSE:
                                theMessage = new InformationResponseMessage(Integer.parseInt(sequence, 16), payload);
                                break;
                            case REALTIMECLOCK_GET_RESPONSE:
                                theMessage = new RealTimeClockGetResponseMessage(Integer.parseInt(sequence, 16),
                                        payload);
                                break;
                            case CLOCK_GET_RESPONSE:
                                theMessage = new ClockGetResponseMessage(Integer.parseInt(sequence, 16), payload);
                                break;
                            case POWER_BUFFER_RESPONSE:
                                theMessage = new PowerBufferResponseMessage(Integer.parseInt(sequence, 16), payload);
                                break;
                            case POWER_INFORMATION_RESPONSE:
                                theMessage = new PowerInformationResponseMessage(Integer.parseInt(sequence, 16),
                                        payload);
                                break;
                            default:
                                logger.debug("Received unrecognized command:{}", command);
                                break;
                        }
                        ;

                        if (theMessage != null) {
                            try {
                                receiveLock.lock();
                                receivedQueue.put(theMessage);
                                receiveLock.unlock();
                            } catch (InterruptedException e) {
                                logger.error(
                                        "Error queueing Plugwise protocol data unit: command:{} sequence:{} payload:{}",
                                        MessageType.forValue(Integer.parseInt(command, 16)),
                                        Integer.parseInt(sequence, 16), payload);
                            }
                        }
                    } else {
                        logger.error("Plugwise protocol CRC error: {} does not match {} in message", calculatedCRC,
                                CRC);
                    }
                } else {
                    logger.debug("Plugwise protocol header error: {} in message {}", protocolHeader, response);
                }
            } else {
                if (!response.contains("APSRequestNodeInfo")) {
                    logger.error("Plugwise protocol message error: {} ", response);
                }
            }
        }
    }

    @Override
    public boolean processMessage(Message message) {

        if (message != null) {
            // deal with the messages that are destined to a very specific plugwise device, and only if we already have
            // a reference to them
            switch (message.getType()) {

                case ACKNOWLEDGEMENT:
                    if (((AcknowledgeMessage) message).isExtended()) {

                        switch (((AcknowledgeMessage) message).getExtensionCode()) {

                            case CIRCLEPLUS:
                                CirclePlus circlePlus11 = (CirclePlus) getDeviceByMAC(
                                        ((AcknowledgeMessage) message).getCirclePlusMAC());
                                if (!((AcknowledgeMessage) message).getCirclePlusMAC().equals("")
                                        && circlePlus11 == null) {
                                    circlePlus11 = new CirclePlus(((AcknowledgeMessage) message).getCirclePlusMAC(),
                                            this);
                                    plugwiseDeviceCache.add(circlePlus11);
                                    logger.debug("Added a CirclePlus with MAC {} to the cache", circlePlus11.getMAC());
                                }
                                circlePlus11.updateInformation();
                                circlePlus11.calibrate();
                                circlePlus11.setClock();

                                if (circlePlus11 != null) {
                                    // initiate a "role call" request in the network
                                    circlePlus11.roleCall(0);
                                }
                                break;
                            case TIMEOUT:

                                // we put the message back in the queue, without tagging it
                                logger.error("Timeout while sending: {}", message);

                                // traverse the sent Q for the
                                Iterator<Message> messageIterator = sentQueue.iterator();
                                Message aMessage = null;
                                while (messageIterator.hasNext()) {
                                    aMessage = messageIterator.next();
                                    if (aMessage.getSequenceNumber() == message.getSequenceNumber()) {
                                        logger.debug("Timeout: removing from the sentQueue: {}", aMessage);
                                        sentQueue.remove(aMessage);
                                        break;
                                    }
                                }

                                if (aMessage != null) {
                                    // reset the sequence number and put it back in the send Q
                                    aMessage.setSequenceNumber(0);
                                    sendMessage(aMessage);
                                }

                                return false;

                            case ON:
                                // Protocol Reverse Engineering: We have to decide whether we trust the ACK messages
                                // sent back to the Stick or not.
                                // If we do, then uncomment this line. If not, we will rely on a formal
                                // DEVICE_INFORMATION_REQUEST to get
                                // the real state of the Circle(+)
                                // postUpdate(((AcknowledgeMessage)message).getExtendedMAC(),
                                // PlugwiseCommandType.CURRENTSTATE, ((AcknowledgeMessage)message).isOn());

                                break;

                            case OFF:
                                // Protocol Reverse Engineering: : Idem as in ON
                                // postUpdate(((AcknowledgeMessage)message).getExtendedMAC(),
                                // PlugwiseCommandType.CURRENTSTATE, ((AcknowledgeMessage)message).isOff());

                                break;

                            default:
                                logger.debug("Plugwise Unknown Acknowledgement message Extension");
                                break;

                        }

                    }
                    return true;

                case INITIALISE_RESPONSE:
                    MAC = ((InitialiseResponseMessage) message).getMAC();
                    initialised = true;

                    // is the network online?
                    if (((InitialiseResponseMessage) message).isOnline()) {

                        CirclePlus circlePlus = (CirclePlus) getDeviceByMAC(
                                ((InitialiseResponseMessage) message).getCirclePlusMAC());
                        if (!((InitialiseResponseMessage) message).getCirclePlusMAC().equals("")
                                && circlePlus == null) {
                            circlePlus = new CirclePlus(((InitialiseResponseMessage) message).getCirclePlusMAC(), this);
                            plugwiseDeviceCache.add(circlePlus);
                            logger.debug("Added a CirclePlus with MAC {} to the cache", circlePlus.getMAC());
                        }
                        circlePlus.updateInformation();
                        circlePlus.calibrate();
                        circlePlus.setClock();

                        if (circlePlus != null) {
                            // initiate a "role call" request in the network
                            circlePlus.roleCall(0);
                        }
                    } else {
                        logger.debug("The network is not online. nothing to do here");
                    }
                    return true;

                case NODE_AVAILABLE:
                    String node = ((NodeAvailableMessage) message).getMAC();

                    Circle someCircle = (Circle) getDeviceByMAC(node);
                    if (someCircle == null) {
                        Circle newCircle = new Circle(node, this, node);
                        plugwiseDeviceCache.add(newCircle);

                        // confirm to the new node that it is added to the network
                        NodeAvailableResponseMessage response = new NodeAvailableResponseMessage(true, node);
                        sendMessage(response);

                        newCircle.updateInformation();
                        newCircle.calibrate();
                    }

                    return true;

                default:
                    return super.processMessage(message);
            }
        }
        return false;
    }

    private String getCRCFromString(String buffer) {

        int crc = 0x0000;
        int polynomial = 0x1021; // 0001 0000 0010 0001 (0, 5, 12)

        byte[] bytes = new byte[0];
        try {
            bytes = buffer.getBytes("ASCII");
        } catch (UnsupportedEncodingException e) {
            logger.debug("Could not fetch ASCII bytes from String ", buffer);
        }

        for (byte b : bytes) {
            for (int i = 0; i < 8; i++) {
                boolean bit = ((b >> (7 - i) & 1) == 1);
                boolean c15 = ((crc >> 15 & 1) == 1);
                crc <<= 1;
                if (c15 ^ bit) {
                    crc ^= polynomial;
                }
            }
        }

        crc &= 0xffff;

        return (String.format("%04X", crc).toUpperCase());
    }

    public static class PowerInformationJob implements Job {

        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {

            // get the reference to the Stick
            JobDataMap dataMap = context.getJobDetail().getJobDataMap();
            Stick theStick = (Stick) dataMap.get("Stick");
            String MAC = (String) dataMap.get("MAC");

            if (theStick.isInitialised()) {
                PlugwiseDevice device = theStick.getDeviceByMAC(MAC);
                if (device != null) {
                    if (device.getType().equals(DeviceType.Circle) || device.getType().equals(DeviceType.CirclePlus)) {
                        ((Circle) device).updateCurrentEnergy();
                    }
                }
            }
        }
    }

    public static class SendJob implements Job {

        private Stick theStick;

        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {

            // get the reference to the Stick
            JobDataMap dataMap = context.getJobDetail().getJobDataMap();
            theStick = (Stick) dataMap.get("Stick");

            if (theStick.isInitialised()) {
                // loop through the send queue and send out all messages
                Message message = theStick.sendQueue.poll();
                while (message != null) {
                    sendMessage(message);
                    try {
                        Thread.sleep(theStick.interval);
                    } catch (InterruptedException e) {
                        logger.debug("SendJob interrupted while sleeping");
                    }
                    message = theStick.sendQueue.poll();
                }
            }
        }

        private boolean sendMessage(Message message) {
            if (message != null) {
                if (message.getAttempts() < theStick.maxRetries) {
                    message.increaseAttempts();

                    String packedString = PROTOCOL_HEADER + message.toHexString() + PROTOCOL_TRAILER;
                    ByteBuffer bytebuffer = ByteBuffer.allocate(packedString.length());
                    bytebuffer.put(packedString.getBytes());

                    bytebuffer.rewind();
                    theStick.queueLock.lock();

                    try {
                        logger.debug("Sending: {} as {}", message, message.toHexString());
                        theStick.outputChannel.write(bytebuffer);
                    } catch (IOException e) {
                        logger.error("Error writing '{}' to serial port {}: {}", packedString, theStick.port,
                                e.getMessage());
                    }

                    // wait for the confirmation message by inspecting the received Q

                    Message lastMessage = null;

                    while (lastMessage == null) {

                        theStick.receiveLock.lock();
                        Iterator<Message> messageIterator = theStick.receivedQueue.iterator();
                        while (messageIterator.hasNext()) {
                            Message aMessage = messageIterator.next();

                            if (aMessage.getType().equals(MessageType.ACKNOWLEDGEMENT)) {
                                if (!((AcknowledgeMessage) aMessage).isExtended()) {
                                    lastMessage = aMessage;
                                    logger.debug("Removing from receivedQueue: {}", lastMessage);
                                    theStick.receivedQueue.remove(lastMessage);
                                    break;
                                }
                            }
                        }
                        theStick.receiveLock.unlock();
                    }

                    AcknowledgeMessage ack = (AcknowledgeMessage) lastMessage;

                    if (!ack.isSuccess()) {
                        if (ack.isError()) {
                            logger.error("Error sending: Negative ACK: {}", packedString);
                        }

                    } else {
                        // update the sent message with the new sequence number
                        message.setSequenceNumber(ack.getSequenceNumber());

                        // place the sent message in the sent Q
                        try {
                            logger.debug("Adding to sentQueue: {}", message);
                            if (theStick.sentQueue.size() == maxBufferSize) {
                                // For some @#$@#$ reason plugwise devices, or the Stick, does not send responses
                                // to Requests. They clog the sentQueue. Let's flush some part of the queue
                                Message someMessage = theStick.sentQueue.poll();
                                logger.debug("Flushing from sentQueue: {}", someMessage);

                            }
                            theStick.sentQueue.put(message);
                        } catch (InterruptedException e) {
                            logger.error("Interrupted while adding to sentQueue: {}", message);
                        }
                    }

                    theStick.queueLock.unlock();
                    return true;

                } else {
                    // max attempts reached
                    // we give up, and to a network reset
                    logger.error(
                            "Giving finally up on Plugwise protocol data unit after attempts: {} MAC:{} command:{} sequence:{} payload:{}",
                            message.getAttempts(), message.getMAC(), message.getType(), message.getSequenceNumber(),
                            message.getPayLoad());
                }
            }
            return false;
        }
    }

    public class SendJobListener implements JobListener {

        private String name;

        public SendJobListener(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public void jobToBeExecuted(JobExecutionContext context) {
            // do something with the event
        }

        @Override
        public void jobWasExecuted(JobExecutionContext context, JobExecutionException jobException) {

            // get the reference to the Stick
            JobDataMap dataMap = context.getJobDetail().getJobDataMap();
            Stick theStick = (Stick) dataMap.get("Stick");

            // logger.debug("SendJobListener: SJobListener reschedule a job");

            Scheduler sched = null;
            try {
                sched = StdSchedulerFactory.getDefaultScheduler();
            } catch (SchedulerException e) {
                logger.error("Error getting a reference to the Quartz Scheduler");
            }

            JobDataMap map = new JobDataMap();
            map.put("Stick", theStick);

            Stick.counter++;

            JobDetail job = newJob(SendJob.class).withIdentity("Send-" + Stick.counter, "Plugwise").usingJobData(map)
                    .build();

            Trigger trigger = newTrigger().withIdentity("Send-" + Stick.counter, "Plugwise").startNow().build();

            try {
                sched.getListenerManager().addJobListener(new SendJobListener("JobListener-" + job.getKey().toString()),
                        KeyMatcher.keyEquals(job.getKey()));
            } catch (SchedulerException e1) {
                logger.error("An exception occured while attaching a Quartz Send Job Listener");
            }

            try {
                sched.scheduleJob(job, trigger);
            } catch (SchedulerException e) {
                logger.error("Error scheduling a job with the Quartz Scheduler : {}", e.getMessage());
            }

        }

        @Override
        public void jobExecutionVetoed(JobExecutionContext context) {
            // do something with the event
        }
    }

    public static class ProcessMessageJob implements Job {

        private Stick theStick;

        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {

            // get the reference to the Stick
            JobDataMap dataMap = context.getJobDetail().getJobDataMap();
            theStick = (Stick) dataMap.get("Stick");

            if (theStick.isInitialised()) {
                theStick.queueLock.lock();
                Message message = theStick.receivedQueue.poll();
                theStick.queueLock.unlock();

                if (message != null) {
                    PlugwiseDevice target = theStick.getDeviceByMAC(message.getMAC());

                    boolean result = false;

                    if (target != null) {
                        result = target.processMessage(message);
                    } else {
                        // if we can not find the target MAC for this message, we let the stick deal with it
                        result = theStick.processMessage(message);
                    }

                    // after processing the response to a message, we remove any reference to the original request
                    // stored in the sent Q
                    // WARNING: We assume that each request sent out can only be followed bye EXACTLY ONE response - so
                    // far it seems that the PW protocol is operating in that way

                    if (result) {
                        Iterator<Message> messageIterator = theStick.sentQueue.iterator();
                        while (messageIterator.hasNext()) {
                            Message aMessage = messageIterator.next();
                            if (aMessage.getSequenceNumber() == message.getSequenceNumber()) {
                                logger.debug("Removing from sentQueue: {}", aMessage);
                                theStick.sentQueue.remove(aMessage);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    public static class PowerBufferJob implements Job {

        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {
            // get the reference to the Stick
            JobDataMap dataMap = context.getJobDetail().getJobDataMap();
            Stick theStick = (Stick) dataMap.get("Stick");
            String MAC = (String) dataMap.get("MAC");

            if (theStick.isInitialised()) {
                PlugwiseDevice device = theStick.getDeviceByMAC(MAC);
                if (device != null) {
                    if (device.getType().equals(DeviceType.Circle) || device.getType().equals(DeviceType.CirclePlus)) {
                        ((Circle) device).updateEnergy(false);
                    }
                }
            }
        }
    }

    public static class ClockJob implements Job {

        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {
            // get the reference to the Stick
            JobDataMap dataMap = context.getJobDetail().getJobDataMap();
            Stick theStick = (Stick) dataMap.get("Stick");
            String MAC = (String) dataMap.get("MAC");

            if (theStick.isInitialised()) {
                PlugwiseDevice device = theStick.getDeviceByMAC(MAC);
                if (device != null) {
                    if (device.getType().equals(DeviceType.Circle) || device.getType().equals(DeviceType.CirclePlus)) {
                        ((Circle) device).updateSystemClock();
                    }
                }
            }
        }
    }

    public static class RealTimeClockJob implements Job {

        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {
            // get the reference to the Stick
            JobDataMap dataMap = context.getJobDetail().getJobDataMap();
            Stick theStick = (Stick) dataMap.get("Stick");
            String MAC = (String) dataMap.get("MAC");

            if (theStick.isInitialised()) {
                PlugwiseDevice device = theStick.getDeviceByMAC(MAC);
                if (device != null) {
                    if (device.getType().equals(DeviceType.CirclePlus)) {
                        ((CirclePlus) device).updateRealTimeClock();
                    }
                }
            }
        }
    }

    public static class InformationJob implements Job {

        @Override
        public void execute(JobExecutionContext context) throws JobExecutionException {
            // get the reference to the Stick
            JobDataMap dataMap = context.getJobDetail().getJobDataMap();
            Stick theStick = (Stick) dataMap.get("Stick");
            String MAC = (String) dataMap.get("MAC");

            if (theStick.isInitialised()) {
                PlugwiseDevice device = theStick.getDeviceByMAC(MAC);
                if (device != null) {
                    if (device.getType().equals(DeviceType.Circle) || device.getType().equals(DeviceType.CirclePlus)) {
                        ((Circle) device).updateInformation();
                    }
                }
            }
        }
    }
}
