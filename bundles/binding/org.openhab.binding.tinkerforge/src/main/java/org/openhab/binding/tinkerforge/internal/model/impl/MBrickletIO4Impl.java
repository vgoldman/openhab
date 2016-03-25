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
import java.util.Collection;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.notify.NotificationChain;
import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;
import org.eclipse.emf.ecore.impl.ENotificationImpl;
import org.eclipse.emf.ecore.impl.MinimalEObjectImpl;
import org.eclipse.emf.ecore.util.EObjectContainmentWithInverseEList;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.eclipse.emf.ecore.util.InternalEList;
import org.openhab.binding.tinkerforge.internal.LoggerConstants;
import org.openhab.binding.tinkerforge.internal.TinkerforgeErrorHandler;
import org.openhab.binding.tinkerforge.internal.model.DigitalActorIO4;
import org.openhab.binding.tinkerforge.internal.model.DigitalSensorIO4;
import org.openhab.binding.tinkerforge.internal.model.IO4Device;
import org.openhab.binding.tinkerforge.internal.model.InterruptListener;
import org.openhab.binding.tinkerforge.internal.model.MBrickd;
import org.openhab.binding.tinkerforge.internal.model.MBrickletIO4;
import org.openhab.binding.tinkerforge.internal.model.MSubDevice;
import org.openhab.binding.tinkerforge.internal.model.MSubDeviceHolder;
import org.openhab.binding.tinkerforge.internal.model.MTFConfigConsumer;
import org.openhab.binding.tinkerforge.internal.model.ModelFactory;
import org.openhab.binding.tinkerforge.internal.model.ModelPackage;
import org.openhab.binding.tinkerforge.internal.model.TFInterruptListenerConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tinkerforge.BrickletIO4;
import com.tinkerforge.IPConnection;
import com.tinkerforge.NotConnectedException;
import com.tinkerforge.TimeoutException;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>MBricklet IO4</b></em>'.
 *
 * @author Theo Weiss
 * @since 1.5.0
 *        <!-- end-user-doc -->
 *        <p>
 *        The following features are implemented:
 *        <ul>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getLogger <em>Logger</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getUid <em>Uid</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#isPoll <em>Poll</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getEnabledA <em>Enabled A</em>
 *        }</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getTinkerforgeDevice
 *        <em>Tinkerforge Device</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getIpConnection
 *        <em>Ip Connection</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getConnectedUid
 *        <em>Connected Uid</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getPosition <em>Position</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getDeviceIdentifier
 *        <em>Device Identifier</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getName <em>Name</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getBrickd <em>Brickd</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getMsubdevices
 *        <em>Msubdevices</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getDebouncePeriod
 *        <em>Debounce Period</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getTfConfig <em>Tf Config</em>
 *        }</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.MBrickletIO4Impl#getDeviceType
 *        <em>Device Type</em>}</li>
 *        </ul>
 *        </p>
 *
 * @generated
 */
public class MBrickletIO4Impl extends MinimalEObjectImpl.Container implements MBrickletIO4 {
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
    protected BrickletIO4 tinkerforgeDevice;

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
     * The cached value of the '{@link #getMsubdevices() <em>Msubdevices</em>}' containment reference list.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getMsubdevices()
     * @generated
     * @ordered
     */
    protected EList<IO4Device> msubdevices;

    /**
     * The default value of the '{@link #getDebouncePeriod() <em>Debounce Period</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDebouncePeriod()
     * @generated
     * @ordered
     */
    protected static final long DEBOUNCE_PERIOD_EDEFAULT = 100L;

    /**
     * The cached value of the '{@link #getDebouncePeriod() <em>Debounce Period</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDebouncePeriod()
     * @generated
     * @ordered
     */
    protected long debouncePeriod = DEBOUNCE_PERIOD_EDEFAULT;

    /**
     * The cached value of the '{@link #getTfConfig() <em>Tf Config</em>}' containment reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getTfConfig()
     * @generated
     * @ordered
     */
    protected TFInterruptListenerConfiguration tfConfig;

    /**
     * The default value of the '{@link #getDeviceType() <em>Device Type</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceType()
     * @generated
     * @ordered
     */
    protected static final String DEVICE_TYPE_EDEFAULT = "bricklet_io4";

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
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    protected MBrickletIO4Impl() {
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
        return ModelPackage.Literals.MBRICKLET_IO4;
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__LOGGER, oldLogger,
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__UID, oldUid, uid));
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__POLL, oldPoll, poll));
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__ENABLED_A, oldEnabledA,
                    enabledA));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public BrickletIO4 getTinkerforgeDevice() {
        return tinkerforgeDevice;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setTinkerforgeDevice(BrickletIO4 newTinkerforgeDevice) {
        BrickletIO4 oldTinkerforgeDevice = tinkerforgeDevice;
        tinkerforgeDevice = newTinkerforgeDevice;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__TINKERFORGE_DEVICE,
                    oldTinkerforgeDevice, tinkerforgeDevice));
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__IP_CONNECTION,
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__CONNECTED_UID,
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__POSITION, oldPosition,
                    position));
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__DEVICE_IDENTIFIER,
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__NAME, oldName, name));
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
        if (eContainerFeatureID() != ModelPackage.MBRICKLET_IO4__BRICKD) {
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
        msgs = eBasicSetContainer((InternalEObject) newBrickd, ModelPackage.MBRICKLET_IO4__BRICKD, msgs);
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
                || (eContainerFeatureID() != ModelPackage.MBRICKLET_IO4__BRICKD && newBrickd != null)) {
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__BRICKD, newBrickd,
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
    public EList<IO4Device> getMsubdevices() {
        if (msubdevices == null) {
            msubdevices = new EObjectContainmentWithInverseEList<IO4Device>(MSubDevice.class, this,
                    ModelPackage.MBRICKLET_IO4__MSUBDEVICES, ModelPackage.MSUB_DEVICE__MBRICK);
        }
        return msubdevices;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public long getDebouncePeriod() {
        return debouncePeriod;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setDebouncePeriod(long newDebouncePeriod) {
        long oldDebouncePeriod = debouncePeriod;
        debouncePeriod = newDebouncePeriod;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__DEBOUNCE_PERIOD,
                    oldDebouncePeriod, debouncePeriod));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public TFInterruptListenerConfiguration getTfConfig() {
        return tfConfig;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    public NotificationChain basicSetTfConfig(TFInterruptListenerConfiguration newTfConfig, NotificationChain msgs) {
        TFInterruptListenerConfiguration oldTfConfig = tfConfig;
        tfConfig = newTfConfig;
        if (eNotificationRequired()) {
            ENotificationImpl notification = new ENotificationImpl(this, Notification.SET,
                    ModelPackage.MBRICKLET_IO4__TF_CONFIG, oldTfConfig, newTfConfig);
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
    public void setTfConfig(TFInterruptListenerConfiguration newTfConfig) {
        if (newTfConfig != tfConfig) {
            NotificationChain msgs = null;
            if (tfConfig != null) {
                msgs = ((InternalEObject) tfConfig).eInverseRemove(this,
                        EOPPOSITE_FEATURE_BASE - ModelPackage.MBRICKLET_IO4__TF_CONFIG, null, msgs);
            }
            if (newTfConfig != null) {
                msgs = ((InternalEObject) newTfConfig).eInverseAdd(this,
                        EOPPOSITE_FEATURE_BASE - ModelPackage.MBRICKLET_IO4__TF_CONFIG, null, msgs);
            }
            msgs = basicSetTfConfig(newTfConfig, msgs);
            if (msgs != null) {
                msgs.dispatch();
            }
        } else if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.MBRICKLET_IO4__TF_CONFIG, newTfConfig,
                    newTfConfig));
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
     * @generated NOT
     */
    @Override
    public void initSubDevices() {
        ModelFactory factory = ModelFactory.eINSTANCE;
        for (int i = 0; i < 4; i++) {
            DigitalSensorIO4 sensor = factory.createDigitalSensorIO4();
            sensor.setUid(getUid());
            String genericDeviceId = String.valueOf(i);
            String subId = "in" + genericDeviceId;
            sensor.setSubId(subId);
            sensor.setPin(i);
            sensor.setGenericDeviceId(genericDeviceId);
            sensor.init();
            sensor.setMbrick(this);
            logger.debug("{} addSubDevice {}", LoggerConstants.TFINIT, subId);
        }
        for (int i = 0; i < 4; i++) {
            DigitalActorIO4 actor = factory.createDigitalActorIO4();
            actor.setUid(getUid());
            String genericDeviceId = String.valueOf(i);
            String subId = "out" + genericDeviceId;
            actor.setSubId(subId);
            actor.setPin(i);
            actor.setGenericDeviceId(genericDeviceId);
            actor.init();
            actor.setMbrick(this);
            logger.debug("{} addSubDevice {}", LoggerConstants.TFINIT, subId);
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
        logger = LoggerFactory.getLogger(MBrickletIO4Impl.class);
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
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("debouncePeriod"))) {
                setDebouncePeriod(tfConfig.getDebouncePeriod());
            }
        }
        try {
            tinkerforgeDevice = new BrickletIO4(getUid(), getIpConnection());
            logger.debug("{} BrickletIO4 setting debouncePeriod to {}", LoggerConstants.TFINIT, getDebouncePeriod());
            tinkerforgeDevice.setDebouncePeriod(getDebouncePeriod());
            tinkerforgeDevice.setInterrupt((short) 15);
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
    public void disable() {
        tinkerforgeDevice = null;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @SuppressWarnings("unchecked")
    @Override
    public NotificationChain eInverseAdd(InternalEObject otherEnd, int featureID, NotificationChain msgs) {
        switch (featureID) {
            case ModelPackage.MBRICKLET_IO4__BRICKD:
                if (eInternalContainer() != null) {
                    msgs = eBasicRemoveFromContainer(msgs);
                }
                return basicSetBrickd((MBrickd) otherEnd, msgs);
            case ModelPackage.MBRICKLET_IO4__MSUBDEVICES:
                return ((InternalEList<InternalEObject>) (InternalEList<?>) getMsubdevices()).basicAdd(otherEnd, msgs);
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
            case ModelPackage.MBRICKLET_IO4__BRICKD:
                return basicSetBrickd(null, msgs);
            case ModelPackage.MBRICKLET_IO4__MSUBDEVICES:
                return ((InternalEList<?>) getMsubdevices()).basicRemove(otherEnd, msgs);
            case ModelPackage.MBRICKLET_IO4__TF_CONFIG:
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
            case ModelPackage.MBRICKLET_IO4__BRICKD:
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
            case ModelPackage.MBRICKLET_IO4__LOGGER:
                return getLogger();
            case ModelPackage.MBRICKLET_IO4__UID:
                return getUid();
            case ModelPackage.MBRICKLET_IO4__POLL:
                return isPoll();
            case ModelPackage.MBRICKLET_IO4__ENABLED_A:
                return getEnabledA();
            case ModelPackage.MBRICKLET_IO4__TINKERFORGE_DEVICE:
                return getTinkerforgeDevice();
            case ModelPackage.MBRICKLET_IO4__IP_CONNECTION:
                return getIpConnection();
            case ModelPackage.MBRICKLET_IO4__CONNECTED_UID:
                return getConnectedUid();
            case ModelPackage.MBRICKLET_IO4__POSITION:
                return getPosition();
            case ModelPackage.MBRICKLET_IO4__DEVICE_IDENTIFIER:
                return getDeviceIdentifier();
            case ModelPackage.MBRICKLET_IO4__NAME:
                return getName();
            case ModelPackage.MBRICKLET_IO4__BRICKD:
                return getBrickd();
            case ModelPackage.MBRICKLET_IO4__MSUBDEVICES:
                return getMsubdevices();
            case ModelPackage.MBRICKLET_IO4__DEBOUNCE_PERIOD:
                return getDebouncePeriod();
            case ModelPackage.MBRICKLET_IO4__TF_CONFIG:
                return getTfConfig();
            case ModelPackage.MBRICKLET_IO4__DEVICE_TYPE:
                return getDeviceType();
        }
        return super.eGet(featureID, resolve, coreType);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @SuppressWarnings("unchecked")
    @Override
    public void eSet(int featureID, Object newValue) {
        switch (featureID) {
            case ModelPackage.MBRICKLET_IO4__LOGGER:
                setLogger((Logger) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__UID:
                setUid((String) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__POLL:
                setPoll((Boolean) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__ENABLED_A:
                setEnabledA((AtomicBoolean) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__TINKERFORGE_DEVICE:
                setTinkerforgeDevice((BrickletIO4) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__IP_CONNECTION:
                setIpConnection((IPConnection) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__CONNECTED_UID:
                setConnectedUid((String) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__POSITION:
                setPosition((Character) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__DEVICE_IDENTIFIER:
                setDeviceIdentifier((Integer) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__NAME:
                setName((String) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__BRICKD:
                setBrickd((MBrickd) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__MSUBDEVICES:
                getMsubdevices().clear();
                getMsubdevices().addAll((Collection<? extends IO4Device>) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__DEBOUNCE_PERIOD:
                setDebouncePeriod((Long) newValue);
                return;
            case ModelPackage.MBRICKLET_IO4__TF_CONFIG:
                setTfConfig((TFInterruptListenerConfiguration) newValue);
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
            case ModelPackage.MBRICKLET_IO4__LOGGER:
                setLogger(LOGGER_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__UID:
                setUid(UID_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__POLL:
                setPoll(POLL_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__ENABLED_A:
                setEnabledA(ENABLED_A_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__TINKERFORGE_DEVICE:
                setTinkerforgeDevice((BrickletIO4) null);
                return;
            case ModelPackage.MBRICKLET_IO4__IP_CONNECTION:
                setIpConnection(IP_CONNECTION_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__CONNECTED_UID:
                setConnectedUid(CONNECTED_UID_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__POSITION:
                setPosition(POSITION_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__DEVICE_IDENTIFIER:
                setDeviceIdentifier(DEVICE_IDENTIFIER_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__NAME:
                setName(NAME_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__BRICKD:
                setBrickd((MBrickd) null);
                return;
            case ModelPackage.MBRICKLET_IO4__MSUBDEVICES:
                getMsubdevices().clear();
                return;
            case ModelPackage.MBRICKLET_IO4__DEBOUNCE_PERIOD:
                setDebouncePeriod(DEBOUNCE_PERIOD_EDEFAULT);
                return;
            case ModelPackage.MBRICKLET_IO4__TF_CONFIG:
                setTfConfig((TFInterruptListenerConfiguration) null);
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
            case ModelPackage.MBRICKLET_IO4__LOGGER:
                return LOGGER_EDEFAULT == null ? logger != null : !LOGGER_EDEFAULT.equals(logger);
            case ModelPackage.MBRICKLET_IO4__UID:
                return UID_EDEFAULT == null ? uid != null : !UID_EDEFAULT.equals(uid);
            case ModelPackage.MBRICKLET_IO4__POLL:
                return poll != POLL_EDEFAULT;
            case ModelPackage.MBRICKLET_IO4__ENABLED_A:
                return ENABLED_A_EDEFAULT == null ? enabledA != null : !ENABLED_A_EDEFAULT.equals(enabledA);
            case ModelPackage.MBRICKLET_IO4__TINKERFORGE_DEVICE:
                return tinkerforgeDevice != null;
            case ModelPackage.MBRICKLET_IO4__IP_CONNECTION:
                return IP_CONNECTION_EDEFAULT == null ? ipConnection != null
                        : !IP_CONNECTION_EDEFAULT.equals(ipConnection);
            case ModelPackage.MBRICKLET_IO4__CONNECTED_UID:
                return CONNECTED_UID_EDEFAULT == null ? connectedUid != null
                        : !CONNECTED_UID_EDEFAULT.equals(connectedUid);
            case ModelPackage.MBRICKLET_IO4__POSITION:
                return position != POSITION_EDEFAULT;
            case ModelPackage.MBRICKLET_IO4__DEVICE_IDENTIFIER:
                return deviceIdentifier != DEVICE_IDENTIFIER_EDEFAULT;
            case ModelPackage.MBRICKLET_IO4__NAME:
                return NAME_EDEFAULT == null ? name != null : !NAME_EDEFAULT.equals(name);
            case ModelPackage.MBRICKLET_IO4__BRICKD:
                return getBrickd() != null;
            case ModelPackage.MBRICKLET_IO4__MSUBDEVICES:
                return msubdevices != null && !msubdevices.isEmpty();
            case ModelPackage.MBRICKLET_IO4__DEBOUNCE_PERIOD:
                return debouncePeriod != DEBOUNCE_PERIOD_EDEFAULT;
            case ModelPackage.MBRICKLET_IO4__TF_CONFIG:
                return tfConfig != null;
            case ModelPackage.MBRICKLET_IO4__DEVICE_TYPE:
                return DEVICE_TYPE_EDEFAULT == null ? deviceType != null : !DEVICE_TYPE_EDEFAULT.equals(deviceType);
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
        if (baseClass == MSubDeviceHolder.class) {
            switch (derivedFeatureID) {
                case ModelPackage.MBRICKLET_IO4__MSUBDEVICES:
                    return ModelPackage.MSUB_DEVICE_HOLDER__MSUBDEVICES;
                default:
                    return -1;
            }
        }
        if (baseClass == InterruptListener.class) {
            switch (derivedFeatureID) {
                case ModelPackage.MBRICKLET_IO4__DEBOUNCE_PERIOD:
                    return ModelPackage.INTERRUPT_LISTENER__DEBOUNCE_PERIOD;
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (derivedFeatureID) {
                case ModelPackage.MBRICKLET_IO4__TF_CONFIG:
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
        if (baseClass == MSubDeviceHolder.class) {
            switch (baseFeatureID) {
                case ModelPackage.MSUB_DEVICE_HOLDER__MSUBDEVICES:
                    return ModelPackage.MBRICKLET_IO4__MSUBDEVICES;
                default:
                    return -1;
            }
        }
        if (baseClass == InterruptListener.class) {
            switch (baseFeatureID) {
                case ModelPackage.INTERRUPT_LISTENER__DEBOUNCE_PERIOD:
                    return ModelPackage.MBRICKLET_IO4__DEBOUNCE_PERIOD;
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (baseFeatureID) {
                case ModelPackage.MTF_CONFIG_CONSUMER__TF_CONFIG:
                    return ModelPackage.MBRICKLET_IO4__TF_CONFIG;
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
        if (baseClass == MSubDeviceHolder.class) {
            switch (baseOperationID) {
                case ModelPackage.MSUB_DEVICE_HOLDER___INIT_SUB_DEVICES:
                    return ModelPackage.MBRICKLET_IO4___INIT_SUB_DEVICES;
                default:
                    return -1;
            }
        }
        if (baseClass == InterruptListener.class) {
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
            case ModelPackage.MBRICKLET_IO4___INIT_SUB_DEVICES:
                initSubDevices();
                return null;
            case ModelPackage.MBRICKLET_IO4___INIT:
                init();
                return null;
            case ModelPackage.MBRICKLET_IO4___ENABLE:
                enable();
                return null;
            case ModelPackage.MBRICKLET_IO4___DISABLE:
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
        result.append(", debouncePeriod: ");
        result.append(debouncePeriod);
        result.append(", deviceType: ");
        result.append(deviceType);
        result.append(')');
        return result.toString();
    }

} // MBrickletIO4Impl
