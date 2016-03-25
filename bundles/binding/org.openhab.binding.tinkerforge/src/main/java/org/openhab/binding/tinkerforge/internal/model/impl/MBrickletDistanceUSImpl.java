/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
/**
 */
package org.openhab.binding.tinkerforge.internal.model.impl;

import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.notify.NotificationChain;
import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;
import org.eclipse.emf.ecore.impl.ENotificationImpl;
import org.eclipse.emf.ecore.impl.MinimalEObjectImpl;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.openhab.binding.tinkerforge.internal.LoggerConstants;
import org.openhab.binding.tinkerforge.internal.TinkerforgeErrorHandler;
import org.openhab.binding.tinkerforge.internal.model.CallbackListener;
import org.openhab.binding.tinkerforge.internal.model.MBrickd;
import org.openhab.binding.tinkerforge.internal.model.MBrickletDistanceUS;
import org.openhab.binding.tinkerforge.internal.model.MSensor;
import org.openhab.binding.tinkerforge.internal.model.MTFConfigConsumer;
import org.openhab.binding.tinkerforge.internal.model.ModelPackage;
import org.openhab.binding.tinkerforge.internal.model.TFDistanceUSBrickletConfiguration;
import org.openhab.binding.tinkerforge.internal.tools.Tools;
import org.openhab.binding.tinkerforge.internal.types.DecimalValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tinkerforge.BrickletDistanceUS;
import com.tinkerforge.IPConnection;
import com.tinkerforge.NotConnectedException;
import com.tinkerforge.TimeoutException;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>MBricklet Distance US</b></em>'.
 *
 * @author Theo Weiss
 * @since 1.5.0
 *        <!-- end-user-doc -->
 *        <p>
 *        The following features are implemented:
 *        <ul>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getLogger
 *        <em>Logger</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getUid <em>Uid</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#isPoll <em>Poll</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getEnabledA
 *        <em>Enabled A</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getTinkerforgeDevice
 *        <em>Tinkerforge Device</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getIpConnection
 *        <em>Ip Connection</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getConnectedUid
 *        <em>Connected Uid</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getPosition
 *        <em>Position</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getDeviceIdentifier
 *        <em>Device Identifier</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getName <em>Name</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getBrickd
 *        <em>Brickd</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getSensorValue
 *        <em>Sensor Value</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getTfConfig
 *        <em>Tf Config</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getCallbackPeriod
 *        <em>Callback Period</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getDeviceType
 *        <em>Device Type</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getThreshold
 *        <em>Threshold</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletDistanceUSImpl#getMovingAverage
 *        <em>Moving Average</em>}</li>
 *        </ul>
 *        </p>
 *
 * @generated
 */
public class MBrickletDistanceUSImpl extends MinimalEObjectImpl.Container implements MBrickletDistanceUS {
    /**
     * The default value of the '{@link #getLogger() <em>Logger</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getLogger()
     * @generated
     * @ordered
     */
    protected static final Logger LOGGER_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getLogger() <em>Logger</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getLogger()
     * @generated
     * @ordered
     */
    protected Logger logger = LOGGER_EDEFAULT;

    /**
     * The default value of the '{@link #getUid() <em>Uid</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getUid()
     * @generated
     * @ordered
     */
    protected static final String UID_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getUid() <em>Uid</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getUid()
     * @generated
     * @ordered
     */
    protected String uid = UID_EDEFAULT;

    /**
     * The default value of the '{@link #isPoll() <em>Poll</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #isPoll()
     * @generated
     * @ordered
     */
    protected static final boolean POLL_EDEFAULT = true;

    /**
     * The cached value of the '{@link #isPoll() <em>Poll</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #isPoll()
     * @generated
     * @ordered
     */
    protected boolean poll = POLL_EDEFAULT;

    /**
     * The default value of the '{@link #getEnabledA() <em>Enabled A</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getEnabledA()
     * @generated
     * @ordered
     */
    protected static final AtomicBoolean ENABLED_A_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getEnabledA() <em>Enabled A</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getEnabledA()
     * @generated
     * @ordered
     */
    protected AtomicBoolean enabledA = ENABLED_A_EDEFAULT;

    /**
     * The cached value of the '{@link #getTinkerforgeDevice() <em>Tinkerforge Device</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getTinkerforgeDevice()
     * @generated
     * @ordered
     */
    protected BrickletDistanceUS tinkerforgeDevice;

    /**
     * The default value of the '{@link #getIpConnection() <em>Ip Connection</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getIpConnection()
     * @generated
     * @ordered
     */
    protected static final IPConnection IP_CONNECTION_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getIpConnection() <em>Ip Connection</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getIpConnection()
     * @generated
     * @ordered
     */
    protected IPConnection ipConnection = IP_CONNECTION_EDEFAULT;

    /**
     * The default value of the '{@link #getConnectedUid() <em>Connected Uid</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getConnectedUid()
     * @generated
     * @ordered
     */
    protected static final String CONNECTED_UID_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getConnectedUid() <em>Connected Uid</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getConnectedUid()
     * @generated
     * @ordered
     */
    protected String connectedUid = CONNECTED_UID_EDEFAULT;

    /**
     * The default value of the '{@link #getPosition() <em>Position</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getPosition()
     * @generated
     * @ordered
     */
    protected static final char POSITION_EDEFAULT = '\u0000';

    /**
     * The cached value of the '{@link #getPosition() <em>Position</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getPosition()
     * @generated
     * @ordered
     */
    protected char position = POSITION_EDEFAULT;

    /**
     * The default value of the '{@link #getDeviceIdentifier() <em>Device Identifier</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceIdentifier()
     * @generated
     * @ordered
     */
    protected static final int DEVICE_IDENTIFIER_EDEFAULT = 0;

    /**
     * The cached value of the '{@link #getDeviceIdentifier() <em>Device Identifier</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceIdentifier()
     * @generated
     * @ordered
     */
    protected int deviceIdentifier = DEVICE_IDENTIFIER_EDEFAULT;

    /**
     * The default value of the '{@link #getName() <em>Name</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getName()
     * @generated
     * @ordered
     */
    protected static final String NAME_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getName() <em>Name</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getName()
     * @generated
     * @ordered
     */
    protected String name = NAME_EDEFAULT;

    /**
     * The cached value of the '{@link #getSensorValue() <em>Sensor Value</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getSensorValue()
     * @generated
     * @ordered
     */
    protected DecimalValue sensorValue;

    /**
     * The cached value of the '{@link #getTfConfig() <em>Tf Config</em>}' containment reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getTfConfig()
     * @generated
     * @ordered
     */
    protected TFDistanceUSBrickletConfiguration tfConfig;

    /**
     * The default value of the '{@link #getCallbackPeriod() <em>Callback Period</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getCallbackPeriod()
     * @generated
     * @ordered
     */
    protected static final long CALLBACK_PERIOD_EDEFAULT = 1000L;

    /**
     * The cached value of the '{@link #getCallbackPeriod() <em>Callback Period</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getCallbackPeriod()
     * @generated
     * @ordered
     */
    protected long callbackPeriod = CALLBACK_PERIOD_EDEFAULT;

    /**
     * The default value of the '{@link #getDeviceType() <em>Device Type</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceType()
     * @generated
     * @ordered
     */
    protected static final String DEVICE_TYPE_EDEFAULT = "bricklet_distanceUS";

    /**
     * The cached value of the '{@link #getDeviceType() <em>Device Type</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceType()
     * @generated
     * @ordered
     */
    protected String deviceType = DEVICE_TYPE_EDEFAULT;

    /**
     * The default value of the '{@link #getThreshold() <em>Threshold</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getThreshold()
     * @generated
     * @ordered
     */
    protected static final BigDecimal THRESHOLD_EDEFAULT = new BigDecimal("0");

    /**
     * The cached value of the '{@link #getThreshold() <em>Threshold</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getThreshold()
     * @generated
     * @ordered
     */
    protected BigDecimal threshold = THRESHOLD_EDEFAULT;

    /**
     * The default value of the '{@link #getMovingAverage() <em>Moving Average</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getMovingAverage()
     * @generated
     * @ordered
     */
    protected static final Short MOVING_AVERAGE_EDEFAULT = new Short((short) 100);

    /**
     * The cached value of the '{@link #getMovingAverage() <em>Moving Average</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getMovingAverage()
     * @generated
     * @ordered
     */
    protected Short movingAverage = MOVING_AVERAGE_EDEFAULT;

    private DistanceListener listener;

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    protected MBrickletDistanceUSImpl() {
        super();
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    protected EClass eStaticClass() {
        return ModelPackage.Literals.MBRICKLET_DISTANCE_US;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public Logger getLogger() {
        return logger;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setLogger(Logger newLogger) {
        Logger oldLogger = logger;
        logger = newLogger;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__LOGGER, oldLogger,
                    logger));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public String getUid() {
        return uid;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setUid(String newUid) {
        String oldUid = uid;
        uid = newUid;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__UID, oldUid,
                    uid));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public boolean isPoll() {
        return poll;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setPoll(boolean newPoll) {
        boolean oldPoll = poll;
        poll = newPoll;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__POLL, oldPoll,
                    poll));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public AtomicBoolean getEnabledA() {
        return enabledA;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setEnabledA(AtomicBoolean newEnabledA) {
        AtomicBoolean oldEnabledA = enabledA;
        enabledA = newEnabledA;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__ENABLED_A,
                    oldEnabledA, enabledA));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public BrickletDistanceUS getTinkerforgeDevice() {
        return tinkerforgeDevice;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setTinkerforgeDevice(BrickletDistanceUS newTinkerforgeDevice) {
        BrickletDistanceUS oldTinkerforgeDevice = tinkerforgeDevice;
        tinkerforgeDevice = newTinkerforgeDevice;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET,
                    ModelPackage.MBRICKLET_DISTANCE_US__TINKERFORGE_DEVICE, oldTinkerforgeDevice, tinkerforgeDevice));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public IPConnection getIpConnection() {
        return ipConnection;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setIpConnection(IPConnection newIpConnection) {
        IPConnection oldIpConnection = ipConnection;
        ipConnection = newIpConnection;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__IP_CONNECTION,
                    oldIpConnection, ipConnection));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public String getConnectedUid() {
        return connectedUid;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setConnectedUid(String newConnectedUid) {
        String oldConnectedUid = connectedUid;
        connectedUid = newConnectedUid;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__CONNECTED_UID,
                    oldConnectedUid, connectedUid));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public char getPosition() {
        return position;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setPosition(char newPosition) {
        char oldPosition = position;
        position = newPosition;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__POSITION,
                    oldPosition, position));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public int getDeviceIdentifier() {
        return deviceIdentifier;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setDeviceIdentifier(int newDeviceIdentifier) {
        int oldDeviceIdentifier = deviceIdentifier;
        deviceIdentifier = newDeviceIdentifier;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__DEVICE_IDENTIFIER,
                    oldDeviceIdentifier, deviceIdentifier));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setName(String newName) {
        String oldName = name;
        name = newName;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__NAME, oldName,
                    name));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public MBrickd getBrickd() {
        if (eContainerFeatureID() != ModelPackage.MBRICKLET_DISTANCE_US__BRICKD) {
            return null;
        }
        return (MBrickd) eContainer();
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    public NotificationChain basicSetBrickd(MBrickd newBrickd, NotificationChain msgs) {
        msgs = eBasicSetContainer((InternalEObject) newBrickd, ModelPackage.MBRICKLET_DISTANCE_US__BRICKD, msgs);
        return msgs;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setBrickd(MBrickd newBrickd) {
        if (newBrickd != eInternalContainer()
                || (eContainerFeatureID() != ModelPackage.MBRICKLET_DISTANCE_US__BRICKD && newBrickd != null)) {
            if (EcoreUtil.isAncestor(this, newBrickd)) {
                throw new IllegalArgumentException("Recursive containment not allowed for " + toString());
            }
            NotificationChain msgs = null;
            if (eInternalContainer() != null) {
                msgs = eBasicRemoveFromContainer(msgs);
            }
            if (newBrickd != null) {
                msgs = ((InternalEObject) newBrickd).eInverseAdd(this, ModelPackage.MBRICKD__MDEVICES, MBrickd.class,
                        msgs);
            }
            msgs = basicSetBrickd(newBrickd, msgs);
            if (msgs != null) {
                msgs.dispatch();
            }
        } else if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__BRICKD, newBrickd,
                    newBrickd));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public DecimalValue getSensorValue() {
        return sensorValue;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setSensorValue(DecimalValue newSensorValue) {
        DecimalValue oldSensorValue = sensorValue;
        sensorValue = newSensorValue;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__SENSOR_VALUE,
                    oldSensorValue, sensorValue));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public TFDistanceUSBrickletConfiguration getTfConfig() {
        return tfConfig;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    public NotificationChain basicSetTfConfig(TFDistanceUSBrickletConfiguration newTfConfig, NotificationChain msgs) {
        TFDistanceUSBrickletConfiguration oldTfConfig = tfConfig;
        tfConfig = newTfConfig;
        if (eNotificationRequired()) {
            ENotificationImpl notification = new ENotificationImpl(this, Notification.SET,
                    ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG, oldTfConfig, newTfConfig);
            if (msgs == null) {
                msgs = notification;
            } else {
                msgs.add(notification);
            }
        }
        return msgs;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setTfConfig(TFDistanceUSBrickletConfiguration newTfConfig) {
        if (newTfConfig != tfConfig) {
            NotificationChain msgs = null;
            if (tfConfig != null) {
                msgs = ((InternalEObject) tfConfig).eInverseRemove(this,
                        EOPPOSITE_FEATURE_BASE - ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG, null, msgs);
            }
            if (newTfConfig != null) {
                msgs = ((InternalEObject) newTfConfig).eInverseAdd(this,
                        EOPPOSITE_FEATURE_BASE - ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG, null, msgs);
            }
            msgs = basicSetTfConfig(newTfConfig, msgs);
            if (msgs != null) {
                msgs.dispatch();
            }
        } else if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG,
                    newTfConfig, newTfConfig));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public long getCallbackPeriod() {
        return callbackPeriod;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setCallbackPeriod(long newCallbackPeriod) {
        long oldCallbackPeriod = callbackPeriod;
        callbackPeriod = newCallbackPeriod;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__CALLBACK_PERIOD,
                    oldCallbackPeriod, callbackPeriod));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public String getDeviceType() {
        return deviceType;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public BigDecimal getThreshold() {
        return threshold;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setThreshold(BigDecimal newThreshold) {
        BigDecimal oldThreshold = threshold;
        threshold = newThreshold;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__THRESHOLD,
                    oldThreshold, threshold));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public Short getMovingAverage() {
        return movingAverage;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setMovingAverage(Short newMovingAverage) {
        Short oldMovingAverage = movingAverage;
        movingAverage = newMovingAverage;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_DISTANCE_US__MOVING_AVERAGE,
                    oldMovingAverage, movingAverage));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void init() {
        setEnabledA(new AtomicBoolean());
        logger = LoggerFactory.getLogger(MBrickletDistanceUSImpl.class);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void fetchSensorValue() {
        try {
            int distance = tinkerforgeDevice.getDistanceValue();
            DecimalValue value = Tools.calculate(distance);
            setSensorValue(value);
        } catch (TimeoutException e) {
            TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_TIMEOUT_EXCEPTION, e);
        } catch (NotConnectedException e) {
            TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_NOT_CONNECTION_EXCEPTION, e);
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void enable() {
        if (tfConfig != null) {
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("threshold"))) {
                setThreshold(tfConfig.getThreshold());
            }
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("callbackPeriod"))) {
                setCallbackPeriod(tfConfig.getCallbackPeriod());
            }
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("movingAverage"))) {
                logger.debug("{} setting movingAverage: {}", LoggerConstants.TFINIT, tfConfig.getMovingAverage());
                setMovingAverage(tfConfig.getMovingAverage());
            }
            try {
                tinkerforgeDevice = new BrickletDistanceUS(getUid(), getIpConnection());
                tinkerforgeDevice.setMovingAverage(getMovingAverage());
                tinkerforgeDevice.setDistanceCallbackPeriod(getCallbackPeriod());
                listener = new DistanceListener();
                tinkerforgeDevice.addDistanceListener(listener);
                fetchSensorValue();
            } catch (TimeoutException e) {
                TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_TIMEOUT_EXCEPTION, e);
            } catch (NotConnectedException e) {
                TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_NOT_CONNECTION_EXCEPTION, e);
            }
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    private class DistanceListener implements BrickletDistanceUS.DistanceListener {

        @Override
        public void distance(int distance) {
            DecimalValue value = Tools.calculate(distance);
            logger.trace("{} got new value {}", LoggerConstants.TFMODELUPDATE, value);
            if (value.compareTo(getSensorValue(), getThreshold()) != 0) {
                logger.trace("{} setting new value {}", LoggerConstants.TFMODELUPDATE, value);
                setSensorValue(value);
            } else {
                logger.trace("{} omitting new value {}", LoggerConstants.TFMODELUPDATE, value);
            }
        }

    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void disable() {
        if (listener != null) {
            tinkerforgeDevice.removeDistanceListener(listener);
        }
        tinkerforgeDevice = null;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public NotificationChain eInverseAdd(InternalEObject otherEnd, int featureID, NotificationChain msgs) {
        switch (featureID) {
            case ModelPackage.MBRICKLET_DISTANCE_US__BRICKD:
                if (eInternalContainer() != null) {
                    msgs = eBasicRemoveFromContainer(msgs);
                }
                return basicSetBrickd((MBrickd) otherEnd, msgs);
        }
        return super.eInverseAdd(otherEnd, featureID, msgs);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public NotificationChain eInverseRemove(InternalEObject otherEnd, int featureID, NotificationChain msgs) {
        switch (featureID) {
            case ModelPackage.MBRICKLET_DISTANCE_US__BRICKD:
                return basicSetBrickd(null, msgs);
            case ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG:
                return basicSetTfConfig(null, msgs);
        }
        return super.eInverseRemove(otherEnd, featureID, msgs);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public NotificationChain eBasicRemoveFromContainerFeature(NotificationChain msgs) {
        switch (eContainerFeatureID()) {
            case ModelPackage.MBRICKLET_DISTANCE_US__BRICKD:
                return eInternalContainer().eInverseRemove(this, ModelPackage.MBRICKD__MDEVICES, MBrickd.class, msgs);
        }
        return super.eBasicRemoveFromContainerFeature(msgs);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public Object eGet(int featureID, boolean resolve, boolean coreType) {
        switch (featureID) {
            case ModelPackage.MBRICKLET_DISTANCE_US__LOGGER:
                return getLogger();
            case ModelPackage.MBRICKLET_DISTANCE_US__UID:
                return getUid();
            case ModelPackage.MBRICKLET_DISTANCE_US__POLL:
                return isPoll();
            case ModelPackage.MBRICKLET_DISTANCE_US__ENABLED_A:
                return getEnabledA();
            case ModelPackage.MBRICKLET_DISTANCE_US__TINKERFORGE_DEVICE:
                return getTinkerforgeDevice();
            case ModelPackage.MBRICKLET_DISTANCE_US__IP_CONNECTION:
                return getIpConnection();
            case ModelPackage.MBRICKLET_DISTANCE_US__CONNECTED_UID:
                return getConnectedUid();
            case ModelPackage.MBRICKLET_DISTANCE_US__POSITION:
                return getPosition();
            case ModelPackage.MBRICKLET_DISTANCE_US__DEVICE_IDENTIFIER:
                return getDeviceIdentifier();
            case ModelPackage.MBRICKLET_DISTANCE_US__NAME:
                return getName();
            case ModelPackage.MBRICKLET_DISTANCE_US__BRICKD:
                return getBrickd();
            case ModelPackage.MBRICKLET_DISTANCE_US__SENSOR_VALUE:
                return getSensorValue();
            case ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG:
                return getTfConfig();
            case ModelPackage.MBRICKLET_DISTANCE_US__CALLBACK_PERIOD:
                return getCallbackPeriod();
            case ModelPackage.MBRICKLET_DISTANCE_US__DEVICE_TYPE:
                return getDeviceType();
            case ModelPackage.MBRICKLET_DISTANCE_US__THRESHOLD:
                return getThreshold();
            case ModelPackage.MBRICKLET_DISTANCE_US__MOVING_AVERAGE:
                return getMovingAverage();
        }
        return super.eGet(featureID, resolve, coreType);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void eSet(int featureID, Object newValue) {
        switch (featureID) {
            case ModelPackage.MBRICKLET_DISTANCE_US__LOGGER:
                setLogger((Logger) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__UID:
                setUid((String) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__POLL:
                setPoll((Boolean) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__ENABLED_A:
                setEnabledA((AtomicBoolean) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__TINKERFORGE_DEVICE:
                setTinkerforgeDevice((BrickletDistanceUS) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__IP_CONNECTION:
                setIpConnection((IPConnection) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__CONNECTED_UID:
                setConnectedUid((String) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__POSITION:
                setPosition((Character) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__DEVICE_IDENTIFIER:
                setDeviceIdentifier((Integer) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__NAME:
                setName((String) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__BRICKD:
                setBrickd((MBrickd) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__SENSOR_VALUE:
                setSensorValue((DecimalValue) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG:
                setTfConfig((TFDistanceUSBrickletConfiguration) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__CALLBACK_PERIOD:
                setCallbackPeriod((Long) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__THRESHOLD:
                setThreshold((BigDecimal) newValue);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__MOVING_AVERAGE:
                setMovingAverage((Short) newValue);
                return;
        }
        super.eSet(featureID, newValue);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void eUnset(int featureID) {
        switch (featureID) {
            case ModelPackage.MBRICKLET_DISTANCE_US__LOGGER:
                setLogger(LOGGER_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__UID:
                setUid(UID_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__POLL:
                setPoll(POLL_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__ENABLED_A:
                setEnabledA(ENABLED_A_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__TINKERFORGE_DEVICE:
                setTinkerforgeDevice((BrickletDistanceUS) null);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__IP_CONNECTION:
                setIpConnection(IP_CONNECTION_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__CONNECTED_UID:
                setConnectedUid(CONNECTED_UID_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__POSITION:
                setPosition(POSITION_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__DEVICE_IDENTIFIER:
                setDeviceIdentifier(DEVICE_IDENTIFIER_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__NAME:
                setName(NAME_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__BRICKD:
                setBrickd((MBrickd) null);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__SENSOR_VALUE:
                setSensorValue((DecimalValue) null);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG:
                setTfConfig((TFDistanceUSBrickletConfiguration) null);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__CALLBACK_PERIOD:
                setCallbackPeriod(CALLBACK_PERIOD_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__THRESHOLD:
                setThreshold(THRESHOLD_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_DISTANCE_US__MOVING_AVERAGE:
                setMovingAverage(MOVING_AVERAGE_EDEFAULT);
                return;
        }
        super.eUnset(featureID);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public boolean eIsSet(int featureID) {
        switch (featureID) {
            case ModelPackage.MBRICKLET_DISTANCE_US__LOGGER:
                return LOGGER_EDEFAULT == null ? logger != null : !LOGGER_EDEFAULT.equals(logger);
            case ModelPackage.MBRICKLET_DISTANCE_US__UID:
                return UID_EDEFAULT == null ? uid != null : !UID_EDEFAULT.equals(uid);
            case ModelPackage.MBRICKLET_DISTANCE_US__POLL:
                return poll != POLL_EDEFAULT;
            case ModelPackage.MBRICKLET_DISTANCE_US__ENABLED_A:
                return ENABLED_A_EDEFAULT == null ? enabledA != null : !ENABLED_A_EDEFAULT.equals(enabledA);
            case ModelPackage.MBRICKLET_DISTANCE_US__TINKERFORGE_DEVICE:
                return tinkerforgeDevice != null;
            case ModelPackage.MBRICKLET_DISTANCE_US__IP_CONNECTION:
                return IP_CONNECTION_EDEFAULT == null ? ipConnection != null
                        : !IP_CONNECTION_EDEFAULT.equals(ipConnection);
            case ModelPackage.MBRICKLET_DISTANCE_US__CONNECTED_UID:
                return CONNECTED_UID_EDEFAULT == null ? connectedUid != null
                        : !CONNECTED_UID_EDEFAULT.equals(connectedUid);
            case ModelPackage.MBRICKLET_DISTANCE_US__POSITION:
                return position != POSITION_EDEFAULT;
            case ModelPackage.MBRICKLET_DISTANCE_US__DEVICE_IDENTIFIER:
                return deviceIdentifier != DEVICE_IDENTIFIER_EDEFAULT;
            case ModelPackage.MBRICKLET_DISTANCE_US__NAME:
                return NAME_EDEFAULT == null ? name != null : !NAME_EDEFAULT.equals(name);
            case ModelPackage.MBRICKLET_DISTANCE_US__BRICKD:
                return getBrickd() != null;
            case ModelPackage.MBRICKLET_DISTANCE_US__SENSOR_VALUE:
                return sensorValue != null;
            case ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG:
                return tfConfig != null;
            case ModelPackage.MBRICKLET_DISTANCE_US__CALLBACK_PERIOD:
                return callbackPeriod != CALLBACK_PERIOD_EDEFAULT;
            case ModelPackage.MBRICKLET_DISTANCE_US__DEVICE_TYPE:
                return DEVICE_TYPE_EDEFAULT == null ? deviceType != null : !DEVICE_TYPE_EDEFAULT.equals(deviceType);
            case ModelPackage.MBRICKLET_DISTANCE_US__THRESHOLD:
                return THRESHOLD_EDEFAULT == null ? threshold != null : !THRESHOLD_EDEFAULT.equals(threshold);
            case ModelPackage.MBRICKLET_DISTANCE_US__MOVING_AVERAGE:
                return MOVING_AVERAGE_EDEFAULT == null ? movingAverage != null
                        : !MOVING_AVERAGE_EDEFAULT.equals(movingAverage);
        }
        return super.eIsSet(featureID);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public int eBaseStructuralFeatureID(int derivedFeatureID, Class<?> baseClass) {
        if (baseClass == MSensor.class) {
            switch (derivedFeatureID) {
                case ModelPackage.MBRICKLET_DISTANCE_US__SENSOR_VALUE:
                    return ModelPackage.MSENSOR__SENSOR_VALUE;
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (derivedFeatureID) {
                case ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG:
                    return ModelPackage.MTF_CONFIG_CONSUMER__TF_CONFIG;
                default:
                    return -1;
            }
        }
        if (baseClass == CallbackListener.class) {
            switch (derivedFeatureID) {
                case ModelPackage.MBRICKLET_DISTANCE_US__CALLBACK_PERIOD:
                    return ModelPackage.CALLBACK_LISTENER__CALLBACK_PERIOD;
                default:
                    return -1;
            }
        }
        return super.eBaseStructuralFeatureID(derivedFeatureID, baseClass);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public int eDerivedStructuralFeatureID(int baseFeatureID, Class<?> baseClass) {
        if (baseClass == MSensor.class) {
            switch (baseFeatureID) {
                case ModelPackage.MSENSOR__SENSOR_VALUE:
                    return ModelPackage.MBRICKLET_DISTANCE_US__SENSOR_VALUE;
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (baseFeatureID) {
                case ModelPackage.MTF_CONFIG_CONSUMER__TF_CONFIG:
                    return ModelPackage.MBRICKLET_DISTANCE_US__TF_CONFIG;
                default:
                    return -1;
            }
        }
        if (baseClass == CallbackListener.class) {
            switch (baseFeatureID) {
                case ModelPackage.CALLBACK_LISTENER__CALLBACK_PERIOD:
                    return ModelPackage.MBRICKLET_DISTANCE_US__CALLBACK_PERIOD;
                default:
                    return -1;
            }
        }
        return super.eDerivedStructuralFeatureID(baseFeatureID, baseClass);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public int eDerivedOperationID(int baseOperationID, Class<?> baseClass) {
        if (baseClass == MSensor.class) {
            switch (baseOperationID) {
                case ModelPackage.MSENSOR___FETCH_SENSOR_VALUE:
                    return ModelPackage.MBRICKLET_DISTANCE_US___FETCH_SENSOR_VALUE;
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (baseOperationID) {
                default:
                    return -1;
            }
        }
        if (baseClass == CallbackListener.class) {
            switch (baseOperationID) {
                default:
                    return -1;
            }
        }
        return super.eDerivedOperationID(baseOperationID, baseClass);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public Object eInvoke(int operationID, EList<?> arguments) throws InvocationTargetException {
        switch (operationID) {
            case ModelPackage.MBRICKLET_DISTANCE_US___INIT:
                init();
                return null;
            case ModelPackage.MBRICKLET_DISTANCE_US___FETCH_SENSOR_VALUE:
                fetchSensorValue();
                return null;
            case ModelPackage.MBRICKLET_DISTANCE_US___ENABLE:
                enable();
                return null;
            case ModelPackage.MBRICKLET_DISTANCE_US___DISABLE:
                disable();
                return null;
        }
        return super.eInvoke(operationID, arguments);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public String toString() {
        if (eIsProxy()) {
            return super.toString();
        }

        StringBuffer result = new StringBuffer(super.toString());
        result.append(" (logger: ");
        result.append(logger);
        result.append(", uid: ");
        result.append(uid);
        result.append(", poll: ");
        result.append(poll);
        result.append(", enabledA: ");
        result.append(enabledA);
        result.append(", tinkerforgeDevice: ");
        result.append(tinkerforgeDevice);
        result.append(", ipConnection: ");
        result.append(ipConnection);
        result.append(", connectedUid: ");
        result.append(connectedUid);
        result.append(", position: ");
        result.append(position);
        result.append(", deviceIdentifier: ");
        result.append(deviceIdentifier);
        result.append(", name: ");
        result.append(name);
        result.append(", sensorValue: ");
        result.append(sensorValue);
        result.append(", callbackPeriod: ");
        result.append(callbackPeriod);
        result.append(", deviceType: ");
        result.append(deviceType);
        result.append(", threshold: ");
        result.append(threshold);
        result.append(", movingAverage: ");
        result.append(movingAverage);
        result.append(')');
        return result.toString();
    }

} // MBrickletDistanceUSImpl
