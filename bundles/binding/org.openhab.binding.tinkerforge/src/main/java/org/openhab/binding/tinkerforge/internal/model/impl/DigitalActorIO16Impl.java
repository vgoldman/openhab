/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.tinkerforge.internal.model.impl;

import java.lang.reflect.InvocationTargetException;
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
import org.openhab.binding.tinkerforge.internal.model.DigitalActorIO16;
import org.openhab.binding.tinkerforge.internal.model.GenericDevice;
import org.openhab.binding.tinkerforge.internal.model.IODevice;
import org.openhab.binding.tinkerforge.internal.model.MBaseDevice;
import org.openhab.binding.tinkerforge.internal.model.MBrickletIO16;
import org.openhab.binding.tinkerforge.internal.model.MSubDevice;
import org.openhab.binding.tinkerforge.internal.model.MSubDeviceHolder;
import org.openhab.binding.tinkerforge.internal.model.MTFConfigConsumer;
import org.openhab.binding.tinkerforge.internal.model.ModelPackage;
import org.openhab.binding.tinkerforge.internal.model.TFIOActorConfiguration;
import org.openhab.binding.tinkerforge.internal.types.HighLowValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tinkerforge.BrickletIO16;
import com.tinkerforge.NotConnectedException;
import com.tinkerforge.TimeoutException;

/**
 * <!-- begin-user-doc -->
 *
 * @author Theo Weiss
 * @since 1.4.0
 *        <!-- end-user-doc -->
 *        <p>
 *        The following features are implemented:
 *        <ul>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getDigitalState
 *        <em>Digital State</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getLogger <em>Logger</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getUid <em>Uid</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#isPoll <em>Poll</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getEnabledA
 *        <em>Enabled A</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getSubId <em>Sub Id</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getMbrick <em>Mbrick</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getGenericDeviceId
 *        <em>Generic Device Id</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getTfConfig
 *        <em>Tf Config</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getDeviceType
 *        <em>Device Type</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getPort <em>Port</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getPin <em>Pin</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#getDefaultState
 *        <em>Default State</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.DigitalActorIO16Impl#isKeepOnReconnect
 *        <em>Keep On Reconnect</em>}</li>
 *        </ul>
 *        </p>
 *
 * @generated
 */
public class DigitalActorIO16Impl extends MinimalEObjectImpl.Container implements DigitalActorIO16 {
    /**
     * The default value of the '{@link #getDigitalState() <em>Digital State</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDigitalState()
     * @generated
     * @ordered
     */
    protected static final HighLowValue DIGITAL_STATE_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getDigitalState() <em>Digital State</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDigitalState()
     * @generated
     * @ordered
     */
    protected HighLowValue digitalState = DIGITAL_STATE_EDEFAULT;

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
     * The default value of the '{@link #getSubId() <em>Sub Id</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getSubId()
     * @generated
     * @ordered
     */
    protected static final String SUB_ID_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getSubId() <em>Sub Id</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getSubId()
     * @generated
     * @ordered
     */
    protected String subId = SUB_ID_EDEFAULT;

    /**
     * The default value of the '{@link #getGenericDeviceId() <em>Generic Device Id</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getGenericDeviceId()
     * @generated
     * @ordered
     */
    protected static final String GENERIC_DEVICE_ID_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getGenericDeviceId() <em>Generic Device Id</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getGenericDeviceId()
     * @generated
     * @ordered
     */
    protected String genericDeviceId = GENERIC_DEVICE_ID_EDEFAULT;

    /**
     * The cached value of the '{@link #getTfConfig() <em>Tf Config</em>}' containment reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getTfConfig()
     * @generated
     * @ordered
     */
    protected TFIOActorConfiguration tfConfig;

    /**
     * The default value of the '{@link #getDeviceType() <em>Device Type</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceType()
     * @generated
     * @ordered
     */
    protected static final String DEVICE_TYPE_EDEFAULT = "io_actuator";

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
     * The default value of the '{@link #getPort() <em>Port</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getPort()
     * @generated
     * @ordered
     */
    protected static final char PORT_EDEFAULT = '\u0000';

    /**
     * The cached value of the '{@link #getPort() <em>Port</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getPort()
     * @generated
     * @ordered
     */
    protected char port = PORT_EDEFAULT;

    /**
     * The default value of the '{@link #getPin() <em>Pin</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getPin()
     * @generated
     * @ordered
     */
    protected static final int PIN_EDEFAULT = 0;

    /**
     * The cached value of the '{@link #getPin() <em>Pin</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getPin()
     * @generated
     * @ordered
     */
    protected int pin = PIN_EDEFAULT;

    /**
     * The default value of the '{@link #getDefaultState() <em>Default State</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDefaultState()
     * @generated
     * @ordered
     */
    protected static final String DEFAULT_STATE_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getDefaultState() <em>Default State</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDefaultState()
     * @generated
     * @ordered
     */
    protected String defaultState = DEFAULT_STATE_EDEFAULT;

    /**
     * The default value of the '{@link #isKeepOnReconnect() <em>Keep On Reconnect</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #isKeepOnReconnect()
     * @generated
     * @ordered
     */
    protected static final boolean KEEP_ON_RECONNECT_EDEFAULT = false;

    /**
     * The cached value of the '{@link #isKeepOnReconnect() <em>Keep On Reconnect</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #isKeepOnReconnect()
     * @generated
     * @ordered
     */
    protected boolean keepOnReconnect = KEEP_ON_RECONNECT_EDEFAULT;

    private int mask;

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    protected DigitalActorIO16Impl() {
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
        return ModelPackage.Literals.DIGITAL_ACTOR_IO16;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public HighLowValue getDigitalState() {
        return digitalState;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setDigitalState(HighLowValue newDigitalState) {
        HighLowValue oldDigitalState = digitalState;
        digitalState = newDigitalState;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__DIGITAL_STATE,
                    oldDigitalState, digitalState));
        }
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__LOGGER, oldLogger,
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__UID, oldUid, uid));
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__POLL, oldPoll,
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__ENABLED_A,
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
    public String getSubId() {
        return subId;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setSubId(String newSubId) {
        String oldSubId = subId;
        subId = newSubId;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__SUB_ID, oldSubId,
                    subId));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public MBrickletIO16 getMbrick() {
        if (eContainerFeatureID() != ModelPackage.DIGITAL_ACTOR_IO16__MBRICK) {
            return null;
        }
        return (MBrickletIO16) eContainer();
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    public NotificationChain basicSetMbrick(MBrickletIO16 newMbrick, NotificationChain msgs) {
        msgs = eBasicSetContainer((InternalEObject) newMbrick, ModelPackage.DIGITAL_ACTOR_IO16__MBRICK, msgs);
        return msgs;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setMbrick(MBrickletIO16 newMbrick) {
        if (newMbrick != eInternalContainer()
                || (eContainerFeatureID() != ModelPackage.DIGITAL_ACTOR_IO16__MBRICK && newMbrick != null)) {
            if (EcoreUtil.isAncestor(this, newMbrick)) {
                throw new IllegalArgumentException("Recursive containment not allowed for " + toString());
            }
            NotificationChain msgs = null;
            if (eInternalContainer() != null) {
                msgs = eBasicRemoveFromContainer(msgs);
            }
            if (newMbrick != null) {
                msgs = ((InternalEObject) newMbrick).eInverseAdd(this, ModelPackage.MSUB_DEVICE_HOLDER__MSUBDEVICES,
                        MSubDeviceHolder.class, msgs);
            }
            msgs = basicSetMbrick(newMbrick, msgs);
            if (msgs != null) {
                msgs.dispatch();
            }
        } else if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__MBRICK, newMbrick,
                    newMbrick));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public String getGenericDeviceId() {
        return genericDeviceId;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setGenericDeviceId(String newGenericDeviceId) {
        String oldGenericDeviceId = genericDeviceId;
        genericDeviceId = newGenericDeviceId;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__GENERIC_DEVICE_ID,
                    oldGenericDeviceId, genericDeviceId));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public TFIOActorConfiguration getTfConfig() {
        return tfConfig;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    public NotificationChain basicSetTfConfig(TFIOActorConfiguration newTfConfig, NotificationChain msgs) {
        TFIOActorConfiguration oldTfConfig = tfConfig;
        tfConfig = newTfConfig;
        if (eNotificationRequired()) {
            ENotificationImpl notification = new ENotificationImpl(this, Notification.SET,
                    ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG, oldTfConfig, newTfConfig);
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
    public void setTfConfig(TFIOActorConfiguration newTfConfig) {
        if (newTfConfig != tfConfig) {
            NotificationChain msgs = null;
            if (tfConfig != null) {
                msgs = ((InternalEObject) tfConfig).eInverseRemove(this,
                        EOPPOSITE_FEATURE_BASE - ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG, null, msgs);
            }
            if (newTfConfig != null) {
                msgs = ((InternalEObject) newTfConfig).eInverseAdd(this,
                        EOPPOSITE_FEATURE_BASE - ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG, null, msgs);
            }
            msgs = basicSetTfConfig(newTfConfig, msgs);
            if (msgs != null) {
                msgs.dispatch();
            }
        } else if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG,
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
    public char getPort() {
        return port;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setPort(char newPort) {
        char oldPort = port;
        port = newPort;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__PORT, oldPort,
                    port));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public int getPin() {
        return pin;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setPin(int newPin) {
        int oldPin = pin;
        pin = newPin;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__PIN, oldPin, pin));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public String getDefaultState() {
        return defaultState;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setDefaultState(String newDefaultState) {
        String oldDefaultState = defaultState;
        defaultState = newDefaultState;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__DEFAULT_STATE,
                    oldDefaultState, defaultState));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public boolean isKeepOnReconnect() {
        return keepOnReconnect;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setKeepOnReconnect(boolean newKeepOnReconnect) {
        boolean oldKeepOnReconnect = keepOnReconnect;
        keepOnReconnect = newKeepOnReconnect;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.DIGITAL_ACTOR_IO16__KEEP_ON_RECONNECT,
                    oldKeepOnReconnect, keepOnReconnect));
        }
    }

    /**
     * <!-- begin-user-doc --> <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void turnDigital(HighLowValue digitalState) {
        BrickletIO16 brickletIO16 = getMbrick().getTinkerforgeDevice();
        try {
            if (digitalState == HighLowValue.HIGH) {
                brickletIO16.setSelectedValues(getPort(), (short) mask, (short) mask);
            } else if (digitalState == HighLowValue.LOW) {
                brickletIO16.setSelectedValues(getPort(), (short) mask, (short) 0);
            } else {
                logger.error("{} unkown digitalState {}", LoggerConstants.TFMODELUPDATE, digitalState);
            }
            setDigitalState(digitalState);
        } catch (TimeoutException e) {
            TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_TIMEOUT_EXCEPTION, e);
        } catch (NotConnectedException e) {
            TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_NOT_CONNECTION_EXCEPTION, e);
        }

    }

    /**
     * <!-- begin-user-doc --> <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void fetchDigitalValue() {
        HighLowValue pinValue = HighLowValue.UNDEF;
        try {
            pinValue = extractValue(getMbrick().getTinkerforgeDevice().getPort(getPort()));
            setDigitalState(pinValue);
        } catch (TimeoutException e) {
            TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_TIMEOUT_EXCEPTION, e);
        } catch (NotConnectedException e) {
            TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_NOT_CONNECTION_EXCEPTION, e);
        }
    }

    /**
     * <!-- begin-user-doc --> <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void init() {
        setEnabledA(new AtomicBoolean());
        poll = true; // don't use the setter to prevent notification
        logger = LoggerFactory.getLogger(DigitalActorIO16Impl.class);
        mask = 00000001 << getPin();
    }

    /**
     * <!-- begin-user-doc --> <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void enable() {
        logger.debug("{} enable called on DigitalActor", LoggerConstants.TFINIT);
        if (tfConfig != null) {
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("defaultState"))) {
                logger.debug("{} setDefaultState: {}", LoggerConstants.TFINIT, tfConfig.getDefaultState());
                setDefaultState(tfConfig.getDefaultState());
            }
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("keepOnReconnect"))) {
                logger.debug("{} keepOnReconnect: {}", LoggerConstants.TFINIT, tfConfig.isKeepOnReconnect());
                setKeepOnReconnect(tfConfig.isKeepOnReconnect());
            }
        }
        String defaultState = getDefaultState();
        try {
            // there seems to be no interrupt support in the upstream api
            if (getMbrick().getBrickd().isReconnected() && isKeepOnReconnect()) {
                logger.debug("{} reconnected: no new port configuration set for {}", LoggerConstants.TFINIT,
                        getSubId());
            } else if (defaultState == null || defaultState.equals("keep")) {
                logger.debug("{} keep: no new port configuration set", LoggerConstants.TFINIT);
            } else if (defaultState.equals("true")) {
                logger.debug("{} setPortconfiguration to state: true", LoggerConstants.TFINIT);
                getMbrick().getTinkerforgeDevice().setPortConfiguration(getPort(), (short) mask,
                        BrickletIO16.DIRECTION_OUT, true);
            } else if (defaultState.equals("false")) {
                logger.debug("{} setPortconfiguration to state: false", LoggerConstants.TFINIT);
                getMbrick().getTinkerforgeDevice().setPortConfiguration(getPort(), (short) mask,
                        BrickletIO16.DIRECTION_OUT, false);
            }
            fetchDigitalValue();
        } catch (TimeoutException e) {
            TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_TIMEOUT_EXCEPTION, e);
        } catch (NotConnectedException e) {
            TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_NOT_CONNECTION_EXCEPTION, e);
        }
    }

    /**
     * 
     * @generated NOT
     */
    private HighLowValue extractValue(int valueMask) {
        HighLowValue value = HighLowValue.UNDEF;
        if ((valueMask & mask) == mask) {
            value = HighLowValue.HIGH;
        } else {
            value = HighLowValue.LOW;
        }
        return value;
    }

    /**
     * <!-- begin-user-doc --> <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void disable() {
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
            case ModelPackage.DIGITAL_ACTOR_IO16__MBRICK:
                if (eInternalContainer() != null) {
                    msgs = eBasicRemoveFromContainer(msgs);
                }
                return basicSetMbrick((MBrickletIO16) otherEnd, msgs);
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
            case ModelPackage.DIGITAL_ACTOR_IO16__MBRICK:
                return basicSetMbrick(null, msgs);
            case ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG:
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
            case ModelPackage.DIGITAL_ACTOR_IO16__MBRICK:
                return eInternalContainer().eInverseRemove(this, ModelPackage.MSUB_DEVICE_HOLDER__MSUBDEVICES,
                        MSubDeviceHolder.class, msgs);
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
            case ModelPackage.DIGITAL_ACTOR_IO16__DIGITAL_STATE:
                return getDigitalState();
            case ModelPackage.DIGITAL_ACTOR_IO16__LOGGER:
                return getLogger();
            case ModelPackage.DIGITAL_ACTOR_IO16__UID:
                return getUid();
            case ModelPackage.DIGITAL_ACTOR_IO16__POLL:
                return isPoll();
            case ModelPackage.DIGITAL_ACTOR_IO16__ENABLED_A:
                return getEnabledA();
            case ModelPackage.DIGITAL_ACTOR_IO16__SUB_ID:
                return getSubId();
            case ModelPackage.DIGITAL_ACTOR_IO16__MBRICK:
                return getMbrick();
            case ModelPackage.DIGITAL_ACTOR_IO16__GENERIC_DEVICE_ID:
                return getGenericDeviceId();
            case ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG:
                return getTfConfig();
            case ModelPackage.DIGITAL_ACTOR_IO16__DEVICE_TYPE:
                return getDeviceType();
            case ModelPackage.DIGITAL_ACTOR_IO16__PORT:
                return getPort();
            case ModelPackage.DIGITAL_ACTOR_IO16__PIN:
                return getPin();
            case ModelPackage.DIGITAL_ACTOR_IO16__DEFAULT_STATE:
                return getDefaultState();
            case ModelPackage.DIGITAL_ACTOR_IO16__KEEP_ON_RECONNECT:
                return isKeepOnReconnect();
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
            case ModelPackage.DIGITAL_ACTOR_IO16__DIGITAL_STATE:
                setDigitalState((HighLowValue) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__LOGGER:
                setLogger((Logger) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__UID:
                setUid((String) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__POLL:
                setPoll((Boolean) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__ENABLED_A:
                setEnabledA((AtomicBoolean) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__SUB_ID:
                setSubId((String) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__MBRICK:
                setMbrick((MBrickletIO16) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__GENERIC_DEVICE_ID:
                setGenericDeviceId((String) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG:
                setTfConfig((TFIOActorConfiguration) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__PORT:
                setPort((Character) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__PIN:
                setPin((Integer) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__DEFAULT_STATE:
                setDefaultState((String) newValue);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__KEEP_ON_RECONNECT:
                setKeepOnReconnect((Boolean) newValue);
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
            case ModelPackage.DIGITAL_ACTOR_IO16__DIGITAL_STATE:
                setDigitalState(DIGITAL_STATE_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__LOGGER:
                setLogger(LOGGER_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__UID:
                setUid(UID_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__POLL:
                setPoll(POLL_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__ENABLED_A:
                setEnabledA(ENABLED_A_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__SUB_ID:
                setSubId(SUB_ID_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__MBRICK:
                setMbrick((MBrickletIO16) null);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__GENERIC_DEVICE_ID:
                setGenericDeviceId(GENERIC_DEVICE_ID_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG:
                setTfConfig((TFIOActorConfiguration) null);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__PORT:
                setPort(PORT_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__PIN:
                setPin(PIN_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__DEFAULT_STATE:
                setDefaultState(DEFAULT_STATE_EDEFAULT);
                return;
            case ModelPackage.DIGITAL_ACTOR_IO16__KEEP_ON_RECONNECT:
                setKeepOnReconnect(KEEP_ON_RECONNECT_EDEFAULT);
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
            case ModelPackage.DIGITAL_ACTOR_IO16__DIGITAL_STATE:
                return DIGITAL_STATE_EDEFAULT == null ? digitalState != null
                        : !DIGITAL_STATE_EDEFAULT.equals(digitalState);
            case ModelPackage.DIGITAL_ACTOR_IO16__LOGGER:
                return LOGGER_EDEFAULT == null ? logger != null : !LOGGER_EDEFAULT.equals(logger);
            case ModelPackage.DIGITAL_ACTOR_IO16__UID:
                return UID_EDEFAULT == null ? uid != null : !UID_EDEFAULT.equals(uid);
            case ModelPackage.DIGITAL_ACTOR_IO16__POLL:
                return poll != POLL_EDEFAULT;
            case ModelPackage.DIGITAL_ACTOR_IO16__ENABLED_A:
                return ENABLED_A_EDEFAULT == null ? enabledA != null : !ENABLED_A_EDEFAULT.equals(enabledA);
            case ModelPackage.DIGITAL_ACTOR_IO16__SUB_ID:
                return SUB_ID_EDEFAULT == null ? subId != null : !SUB_ID_EDEFAULT.equals(subId);
            case ModelPackage.DIGITAL_ACTOR_IO16__MBRICK:
                return getMbrick() != null;
            case ModelPackage.DIGITAL_ACTOR_IO16__GENERIC_DEVICE_ID:
                return GENERIC_DEVICE_ID_EDEFAULT == null ? genericDeviceId != null
                        : !GENERIC_DEVICE_ID_EDEFAULT.equals(genericDeviceId);
            case ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG:
                return tfConfig != null;
            case ModelPackage.DIGITAL_ACTOR_IO16__DEVICE_TYPE:
                return DEVICE_TYPE_EDEFAULT == null ? deviceType != null : !DEVICE_TYPE_EDEFAULT.equals(deviceType);
            case ModelPackage.DIGITAL_ACTOR_IO16__PORT:
                return port != PORT_EDEFAULT;
            case ModelPackage.DIGITAL_ACTOR_IO16__PIN:
                return pin != PIN_EDEFAULT;
            case ModelPackage.DIGITAL_ACTOR_IO16__DEFAULT_STATE:
                return DEFAULT_STATE_EDEFAULT == null ? defaultState != null
                        : !DEFAULT_STATE_EDEFAULT.equals(defaultState);
            case ModelPackage.DIGITAL_ACTOR_IO16__KEEP_ON_RECONNECT:
                return keepOnReconnect != KEEP_ON_RECONNECT_EDEFAULT;
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
        if (baseClass == MBaseDevice.class) {
            switch (derivedFeatureID) {
                case ModelPackage.DIGITAL_ACTOR_IO16__LOGGER:
                    return ModelPackage.MBASE_DEVICE__LOGGER;
                case ModelPackage.DIGITAL_ACTOR_IO16__UID:
                    return ModelPackage.MBASE_DEVICE__UID;
                case ModelPackage.DIGITAL_ACTOR_IO16__POLL:
                    return ModelPackage.MBASE_DEVICE__POLL;
                case ModelPackage.DIGITAL_ACTOR_IO16__ENABLED_A:
                    return ModelPackage.MBASE_DEVICE__ENABLED_A;
                default:
                    return -1;
            }
        }
        if (baseClass == MSubDevice.class) {
            switch (derivedFeatureID) {
                case ModelPackage.DIGITAL_ACTOR_IO16__SUB_ID:
                    return ModelPackage.MSUB_DEVICE__SUB_ID;
                case ModelPackage.DIGITAL_ACTOR_IO16__MBRICK:
                    return ModelPackage.MSUB_DEVICE__MBRICK;
                default:
                    return -1;
            }
        }
        if (baseClass == GenericDevice.class) {
            switch (derivedFeatureID) {
                case ModelPackage.DIGITAL_ACTOR_IO16__GENERIC_DEVICE_ID:
                    return ModelPackage.GENERIC_DEVICE__GENERIC_DEVICE_ID;
                default:
                    return -1;
            }
        }
        if (baseClass == IODevice.class) {
            switch (derivedFeatureID) {
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (derivedFeatureID) {
                case ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG:
                    return ModelPackage.MTF_CONFIG_CONSUMER__TF_CONFIG;
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
        if (baseClass == MBaseDevice.class) {
            switch (baseFeatureID) {
                case ModelPackage.MBASE_DEVICE__LOGGER:
                    return ModelPackage.DIGITAL_ACTOR_IO16__LOGGER;
                case ModelPackage.MBASE_DEVICE__UID:
                    return ModelPackage.DIGITAL_ACTOR_IO16__UID;
                case ModelPackage.MBASE_DEVICE__POLL:
                    return ModelPackage.DIGITAL_ACTOR_IO16__POLL;
                case ModelPackage.MBASE_DEVICE__ENABLED_A:
                    return ModelPackage.DIGITAL_ACTOR_IO16__ENABLED_A;
                default:
                    return -1;
            }
        }
        if (baseClass == MSubDevice.class) {
            switch (baseFeatureID) {
                case ModelPackage.MSUB_DEVICE__SUB_ID:
                    return ModelPackage.DIGITAL_ACTOR_IO16__SUB_ID;
                case ModelPackage.MSUB_DEVICE__MBRICK:
                    return ModelPackage.DIGITAL_ACTOR_IO16__MBRICK;
                default:
                    return -1;
            }
        }
        if (baseClass == GenericDevice.class) {
            switch (baseFeatureID) {
                case ModelPackage.GENERIC_DEVICE__GENERIC_DEVICE_ID:
                    return ModelPackage.DIGITAL_ACTOR_IO16__GENERIC_DEVICE_ID;
                default:
                    return -1;
            }
        }
        if (baseClass == IODevice.class) {
            switch (baseFeatureID) {
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (baseFeatureID) {
                case ModelPackage.MTF_CONFIG_CONSUMER__TF_CONFIG:
                    return ModelPackage.DIGITAL_ACTOR_IO16__TF_CONFIG;
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
        if (baseClass == MBaseDevice.class) {
            switch (baseOperationID) {
                case ModelPackage.MBASE_DEVICE___INIT:
                    return ModelPackage.DIGITAL_ACTOR_IO16___INIT;
                case ModelPackage.MBASE_DEVICE___ENABLE:
                    return ModelPackage.DIGITAL_ACTOR_IO16___ENABLE;
                case ModelPackage.MBASE_DEVICE___DISABLE:
                    return ModelPackage.DIGITAL_ACTOR_IO16___DISABLE;
                default:
                    return -1;
            }
        }
        if (baseClass == MSubDevice.class) {
            switch (baseOperationID) {
                default:
                    return -1;
            }
        }
        if (baseClass == GenericDevice.class) {
            switch (baseOperationID) {
                default:
                    return -1;
            }
        }
        if (baseClass == IODevice.class) {
            switch (baseOperationID) {
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
            case ModelPackage.DIGITAL_ACTOR_IO16___TURN_DIGITAL__HIGHLOWVALUE:
                turnDigital((HighLowValue) arguments.get(0));
                return null;
            case ModelPackage.DIGITAL_ACTOR_IO16___FETCH_DIGITAL_VALUE:
                fetchDigitalValue();
                return null;
            case ModelPackage.DIGITAL_ACTOR_IO16___INIT:
                init();
                return null;
            case ModelPackage.DIGITAL_ACTOR_IO16___ENABLE:
                enable();
                return null;
            case ModelPackage.DIGITAL_ACTOR_IO16___DISABLE:
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
        result.append(" (digitalState: ");
        result.append(digitalState);
        result.append(", logger: ");
        result.append(logger);
        result.append(", uid: ");
        result.append(uid);
        result.append(", poll: ");
        result.append(poll);
        result.append(", enabledA: ");
        result.append(enabledA);
        result.append(", subId: ");
        result.append(subId);
        result.append(", genericDeviceId: ");
        result.append(genericDeviceId);
        result.append(", deviceType: ");
        result.append(deviceType);
        result.append(", port: ");
        result.append(port);
        result.append(", pin: ");
        result.append(pin);
        result.append(", defaultState: ");
        result.append(defaultState);
        result.append(", keepOnReconnect: ");
        result.append(keepOnReconnect);
        result.append(')');
        return result.toString();
    }

} // DigitalActorImpl
