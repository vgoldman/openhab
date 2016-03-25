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
import org.openhab.binding.tinkerforge.internal.model.MBaseDevice;
import org.openhab.binding.tinkerforge.internal.model.MBrickletRemoteSwitch;
import org.openhab.binding.tinkerforge.internal.model.MSubDevice;
import org.openhab.binding.tinkerforge.internal.model.MSubDeviceHolder;
import org.openhab.binding.tinkerforge.internal.model.MTFConfigConsumer;
import org.openhab.binding.tinkerforge.internal.model.ModelPackage;
import org.openhab.binding.tinkerforge.internal.model.RemoteSwitchC;
import org.openhab.binding.tinkerforge.internal.model.RemoteSwitchCConfiguration;
import org.openhab.binding.tinkerforge.internal.types.OnOffValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tinkerforge.BrickletRemoteSwitch;
import com.tinkerforge.NotConnectedException;
import com.tinkerforge.TimeoutException;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Remote Switch C</b></em>'.
 *
 * @author Theo Weiss
 * @since 1.5.0
 *        <!-- end-user-doc -->
 *        <p>
 *        The following features are implemented:
 *        <ul>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getSwitchState
 *        <em>Switch State</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getLogger <em>Logger</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getUid <em>Uid</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#isPoll <em>Poll</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getEnabledA
 *        <em>Enabled A</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getSubId <em>Sub Id</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getMbrick <em>Mbrick</em>}
 *        </li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getTfConfig
 *        <em>Tf Config</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getDeviceType
 *        <em>Device Type</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getSystemCode
 *        <em>System Code</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getDeviceCode
 *        <em>Device Code</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.impl.RemoteSwitchCImpl#getRepeats <em>Repeats</em>}
 *        </li>
 *        </ul>
 *        </p>
 *
 * @generated
 */
public class RemoteSwitchCImpl extends MinimalEObjectImpl.Container implements RemoteSwitchC {
    /**
     * The default value of the '{@link #getSwitchState() <em>Switch State</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getSwitchState()
     * @generated
     * @ordered
     */
    protected static final OnOffValue SWITCH_STATE_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getSwitchState() <em>Switch State</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getSwitchState()
     * @generated
     * @ordered
     */
    protected OnOffValue switchState = SWITCH_STATE_EDEFAULT;

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
     * The cached value of the '{@link #getTfConfig() <em>Tf Config</em>}' containment reference.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getTfConfig()
     * @generated
     * @ordered
     */
    protected RemoteSwitchCConfiguration tfConfig;

    /**
     * The default value of the '{@link #getDeviceType() <em>Device Type</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceType()
     * @generated
     * @ordered
     */
    protected static final String DEVICE_TYPE_EDEFAULT = "remote_switch_c";

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
     * The default value of the '{@link #getSystemCode() <em>System Code</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getSystemCode()
     * @generated
     * @ordered
     */
    protected static final String SYSTEM_CODE_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getSystemCode() <em>System Code</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getSystemCode()
     * @generated
     * @ordered
     */
    protected String systemCode = SYSTEM_CODE_EDEFAULT;

    /**
     * The default value of the '{@link #getDeviceCode() <em>Device Code</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceCode()
     * @generated
     * @ordered
     */
    protected static final Short DEVICE_CODE_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getDeviceCode() <em>Device Code</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getDeviceCode()
     * @generated
     * @ordered
     */
    protected Short deviceCode = DEVICE_CODE_EDEFAULT;

    /**
     * The default value of the '{@link #getRepeats() <em>Repeats</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getRepeats()
     * @generated
     * @ordered
     */
    protected static final Short REPEATS_EDEFAULT = null;

    /**
     * The cached value of the '{@link #getRepeats() <em>Repeats</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @see #getRepeats()
     * @generated
     * @ordered
     */
    protected Short repeats = REPEATS_EDEFAULT;

    private BrickletRemoteSwitch tinkerforgeDevice;

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    protected RemoteSwitchCImpl() {
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
        return ModelPackage.Literals.REMOTE_SWITCH_C;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public OnOffValue getSwitchState() {
        return switchState;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setSwitchState(OnOffValue newSwitchState) {
        OnOffValue oldSwitchState = switchState;
        switchState = newSwitchState;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__SWITCH_STATE,
                    oldSwitchState, switchState));
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__LOGGER, oldLogger,
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__UID, oldUid, uid));
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__POLL, oldPoll, poll));
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__ENABLED_A, oldEnabledA,
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__SUB_ID, oldSubId,
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
    public MBrickletRemoteSwitch getMbrick() {
        if (eContainerFeatureID() != ModelPackage.REMOTE_SWITCH_C__MBRICK) {
            return null;
        }
        return (MBrickletRemoteSwitch) eContainer();
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    public NotificationChain basicSetMbrick(MBrickletRemoteSwitch newMbrick, NotificationChain msgs) {
        msgs = eBasicSetContainer((InternalEObject) newMbrick, ModelPackage.REMOTE_SWITCH_C__MBRICK, msgs);
        return msgs;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setMbrick(MBrickletRemoteSwitch newMbrick) {
        if (newMbrick != eInternalContainer()
                || (eContainerFeatureID() != ModelPackage.REMOTE_SWITCH_C__MBRICK && newMbrick != null)) {
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
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__MBRICK, newMbrick,
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
    public String getSystemCode() {
        return systemCode;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setSystemCode(String newSystemCode) {
        String oldSystemCode = systemCode;
        systemCode = newSystemCode;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__SYSTEM_CODE,
                    oldSystemCode, systemCode));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public Short getDeviceCode() {
        return deviceCode;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setDeviceCode(Short newDeviceCode) {
        Short oldDeviceCode = deviceCode;
        deviceCode = newDeviceCode;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__DEVICE_CODE,
                    oldDeviceCode, deviceCode));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public Short getRepeats() {
        return repeats;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public void setRepeats(Short newRepeats) {
        Short oldRepeats = repeats;
        repeats = newRepeats;
        if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__REPEATS, oldRepeats,
                    repeats));
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    @Override
    public RemoteSwitchCConfiguration getTfConfig() {
        return tfConfig;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated
     */
    public NotificationChain basicSetTfConfig(RemoteSwitchCConfiguration newTfConfig, NotificationChain msgs) {
        RemoteSwitchCConfiguration oldTfConfig = tfConfig;
        tfConfig = newTfConfig;
        if (eNotificationRequired()) {
            ENotificationImpl notification = new ENotificationImpl(this, Notification.SET,
                    ModelPackage.REMOTE_SWITCH_C__TF_CONFIG, oldTfConfig, newTfConfig);
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
    public void setTfConfig(RemoteSwitchCConfiguration newTfConfig) {
        if (newTfConfig != tfConfig) {
            NotificationChain msgs = null;
            if (tfConfig != null) {
                msgs = ((InternalEObject) tfConfig).eInverseRemove(this,
                        EOPPOSITE_FEATURE_BASE - ModelPackage.REMOTE_SWITCH_C__TF_CONFIG, null, msgs);
            }
            if (newTfConfig != null) {
                msgs = ((InternalEObject) newTfConfig).eInverseAdd(this,
                        EOPPOSITE_FEATURE_BASE - ModelPackage.REMOTE_SWITCH_C__TF_CONFIG, null, msgs);
            }
            msgs = basicSetTfConfig(newTfConfig, msgs);
            if (msgs != null) {
                msgs.dispatch();
            }
        } else if (eNotificationRequired()) {
            eNotify(new ENotificationImpl(this, Notification.SET, ModelPackage.REMOTE_SWITCH_C__TF_CONFIG, newTfConfig,
                    newTfConfig));
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
        logger = LoggerFactory.getLogger(RemoteSwitchCImpl.class);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void enable() {
        logger.debug("{} enable called on RemoteSwitchC", LoggerConstants.TFINIT);
        boolean systemCodeFound = false;
        boolean deviceCodeFound = false;
        if (tfConfig != null) {
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("systemCode"))) {
                setSystemCode(tfConfig.getSystemCode());
                systemCodeFound = true;
            } else {
                logger.error("{} systemCode not configured for subid {}", LoggerConstants.TFINITSUB, getSubId());
            }
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("deviceCode"))) {
                setDeviceCode(tfConfig.getDeviceCode());
                deviceCodeFound = true;
            } else {
                logger.error("{} deviceCode not configured for subid {}", LoggerConstants.TFINITSUB, getSubId());
            }
            if (tfConfig.eIsSet(tfConfig.eClass().getEStructuralFeature("repeats"))) {
                setRepeats(tfConfig.getRepeats());
            }
        }
        if (tfConfig == null || !systemCodeFound || !deviceCodeFound) {
            logger.error("{} missing configuration for subid {} device will not work", LoggerConstants.TFINITSUB,
                    getSubId());
        }
        tinkerforgeDevice = getMbrick().getTinkerforgeDevice();
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
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
     * @generated NOT
     */
    @Override
    public void turnSwitch(OnOffValue state) {
        if (state == OnOffValue.UNDEF) {
            logger.warn("got undef state, nothing to be done");
            return;
        }
        if (getDeviceCode() != null && systemCode != null) {
            short switchTo = state == OnOffValue.ON ? BrickletRemoteSwitch.SWITCH_TO_ON
                    : BrickletRemoteSwitch.SWITCH_TO_OFF;
            try {
                int maxRetries = 20;
                int trial = 0;
                while (tinkerforgeDevice.getSwitchingState() == BrickletRemoteSwitch.SWITCHING_STATE_BUSY
                        && trial < maxRetries) {
                    trial++;
                    logger.trace("waiting for ready state {}", trial);
                    Thread.sleep(50);
                }
                if (trial == maxRetries) {
                    logger.error("remote switch doesn't go to ready state in spite of {} retries.", trial);
                    return;
                }
                if (getRepeats() != null) {
                    tinkerforgeDevice.setRepeats(getRepeats());
                }
                logger.debug("switching socket C with systemCode {}, deviceCode {} to {}", getSystemCode().charAt(0),
                        getDeviceCode(), switchTo);
                tinkerforgeDevice.switchSocketC(getSystemCode().charAt(0), getDeviceCode(), switchTo);
                setSwitchState(state);
            } catch (TimeoutException e) {
                TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_TIMEOUT_EXCEPTION, e);
            } catch (NotConnectedException e) {
                TinkerforgeErrorHandler.handleError(this, TinkerforgeErrorHandler.TF_NOT_CONNECTION_EXCEPTION, e);
            } catch (InterruptedException e) {
                logger.warn("retry was interrupted");
            }
        } else {
            logger.error("{} missing configuration for subid {} device will not switch", LoggerConstants.TFINITSUB,
                    getSubId());
        }
    }

    /**
     * <!-- begin-user-doc --> <!-- end-user-doc -->
     * 
     * @generated NOT
     */
    @Override
    public void fetchSwitchState() {
        setSwitchState(getSwitchState()); // trigger a value update to the eventbus
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
            case ModelPackage.REMOTE_SWITCH_C__MBRICK:
                if (eInternalContainer() != null) {
                    msgs = eBasicRemoveFromContainer(msgs);
                }
                return basicSetMbrick((MBrickletRemoteSwitch) otherEnd, msgs);
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
            case ModelPackage.REMOTE_SWITCH_C__MBRICK:
                return basicSetMbrick(null, msgs);
            case ModelPackage.REMOTE_SWITCH_C__TF_CONFIG:
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
            case ModelPackage.REMOTE_SWITCH_C__MBRICK:
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
            case ModelPackage.REMOTE_SWITCH_C__SWITCH_STATE:
                return getSwitchState();
            case ModelPackage.REMOTE_SWITCH_C__LOGGER:
                return getLogger();
            case ModelPackage.REMOTE_SWITCH_C__UID:
                return getUid();
            case ModelPackage.REMOTE_SWITCH_C__POLL:
                return isPoll();
            case ModelPackage.REMOTE_SWITCH_C__ENABLED_A:
                return getEnabledA();
            case ModelPackage.REMOTE_SWITCH_C__SUB_ID:
                return getSubId();
            case ModelPackage.REMOTE_SWITCH_C__MBRICK:
                return getMbrick();
            case ModelPackage.REMOTE_SWITCH_C__TF_CONFIG:
                return getTfConfig();
            case ModelPackage.REMOTE_SWITCH_C__DEVICE_TYPE:
                return getDeviceType();
            case ModelPackage.REMOTE_SWITCH_C__SYSTEM_CODE:
                return getSystemCode();
            case ModelPackage.REMOTE_SWITCH_C__DEVICE_CODE:
                return getDeviceCode();
            case ModelPackage.REMOTE_SWITCH_C__REPEATS:
                return getRepeats();
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
            case ModelPackage.REMOTE_SWITCH_C__SWITCH_STATE:
                setSwitchState((OnOffValue) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__LOGGER:
                setLogger((Logger) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__UID:
                setUid((String) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__POLL:
                setPoll((Boolean) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__ENABLED_A:
                setEnabledA((AtomicBoolean) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__SUB_ID:
                setSubId((String) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__MBRICK:
                setMbrick((MBrickletRemoteSwitch) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__TF_CONFIG:
                setTfConfig((RemoteSwitchCConfiguration) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__SYSTEM_CODE:
                setSystemCode((String) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__DEVICE_CODE:
                setDeviceCode((Short) newValue);
                return;
            case ModelPackage.REMOTE_SWITCH_C__REPEATS:
                setRepeats((Short) newValue);
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
            case ModelPackage.REMOTE_SWITCH_C__SWITCH_STATE:
                setSwitchState(SWITCH_STATE_EDEFAULT);
                return;
            case ModelPackage.REMOTE_SWITCH_C__LOGGER:
                setLogger(LOGGER_EDEFAULT);
                return;
            case ModelPackage.REMOTE_SWITCH_C__UID:
                setUid(UID_EDEFAULT);
                return;
            case ModelPackage.REMOTE_SWITCH_C__POLL:
                setPoll(POLL_EDEFAULT);
                return;
            case ModelPackage.REMOTE_SWITCH_C__ENABLED_A:
                setEnabledA(ENABLED_A_EDEFAULT);
                return;
            case ModelPackage.REMOTE_SWITCH_C__SUB_ID:
                setSubId(SUB_ID_EDEFAULT);
                return;
            case ModelPackage.REMOTE_SWITCH_C__MBRICK:
                setMbrick((MBrickletRemoteSwitch) null);
                return;
            case ModelPackage.REMOTE_SWITCH_C__TF_CONFIG:
                setTfConfig((RemoteSwitchCConfiguration) null);
                return;
            case ModelPackage.REMOTE_SWITCH_C__SYSTEM_CODE:
                setSystemCode(SYSTEM_CODE_EDEFAULT);
                return;
            case ModelPackage.REMOTE_SWITCH_C__DEVICE_CODE:
                setDeviceCode(DEVICE_CODE_EDEFAULT);
                return;
            case ModelPackage.REMOTE_SWITCH_C__REPEATS:
                setRepeats(REPEATS_EDEFAULT);
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
            case ModelPackage.REMOTE_SWITCH_C__SWITCH_STATE:
                return SWITCH_STATE_EDEFAULT == null ? switchState != null : !SWITCH_STATE_EDEFAULT.equals(switchState);
            case ModelPackage.REMOTE_SWITCH_C__LOGGER:
                return LOGGER_EDEFAULT == null ? logger != null : !LOGGER_EDEFAULT.equals(logger);
            case ModelPackage.REMOTE_SWITCH_C__UID:
                return UID_EDEFAULT == null ? uid != null : !UID_EDEFAULT.equals(uid);
            case ModelPackage.REMOTE_SWITCH_C__POLL:
                return poll != POLL_EDEFAULT;
            case ModelPackage.REMOTE_SWITCH_C__ENABLED_A:
                return ENABLED_A_EDEFAULT == null ? enabledA != null : !ENABLED_A_EDEFAULT.equals(enabledA);
            case ModelPackage.REMOTE_SWITCH_C__SUB_ID:
                return SUB_ID_EDEFAULT == null ? subId != null : !SUB_ID_EDEFAULT.equals(subId);
            case ModelPackage.REMOTE_SWITCH_C__MBRICK:
                return getMbrick() != null;
            case ModelPackage.REMOTE_SWITCH_C__TF_CONFIG:
                return tfConfig != null;
            case ModelPackage.REMOTE_SWITCH_C__DEVICE_TYPE:
                return DEVICE_TYPE_EDEFAULT == null ? deviceType != null : !DEVICE_TYPE_EDEFAULT.equals(deviceType);
            case ModelPackage.REMOTE_SWITCH_C__SYSTEM_CODE:
                return SYSTEM_CODE_EDEFAULT == null ? systemCode != null : !SYSTEM_CODE_EDEFAULT.equals(systemCode);
            case ModelPackage.REMOTE_SWITCH_C__DEVICE_CODE:
                return DEVICE_CODE_EDEFAULT == null ? deviceCode != null : !DEVICE_CODE_EDEFAULT.equals(deviceCode);
            case ModelPackage.REMOTE_SWITCH_C__REPEATS:
                return REPEATS_EDEFAULT == null ? repeats != null : !REPEATS_EDEFAULT.equals(repeats);
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
                case ModelPackage.REMOTE_SWITCH_C__LOGGER:
                    return ModelPackage.MBASE_DEVICE__LOGGER;
                case ModelPackage.REMOTE_SWITCH_C__UID:
                    return ModelPackage.MBASE_DEVICE__UID;
                case ModelPackage.REMOTE_SWITCH_C__POLL:
                    return ModelPackage.MBASE_DEVICE__POLL;
                case ModelPackage.REMOTE_SWITCH_C__ENABLED_A:
                    return ModelPackage.MBASE_DEVICE__ENABLED_A;
                default:
                    return -1;
            }
        }
        if (baseClass == MSubDevice.class) {
            switch (derivedFeatureID) {
                case ModelPackage.REMOTE_SWITCH_C__SUB_ID:
                    return ModelPackage.MSUB_DEVICE__SUB_ID;
                case ModelPackage.REMOTE_SWITCH_C__MBRICK:
                    return ModelPackage.MSUB_DEVICE__MBRICK;
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (derivedFeatureID) {
                case ModelPackage.REMOTE_SWITCH_C__TF_CONFIG:
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
                    return ModelPackage.REMOTE_SWITCH_C__LOGGER;
                case ModelPackage.MBASE_DEVICE__UID:
                    return ModelPackage.REMOTE_SWITCH_C__UID;
                case ModelPackage.MBASE_DEVICE__POLL:
                    return ModelPackage.REMOTE_SWITCH_C__POLL;
                case ModelPackage.MBASE_DEVICE__ENABLED_A:
                    return ModelPackage.REMOTE_SWITCH_C__ENABLED_A;
                default:
                    return -1;
            }
        }
        if (baseClass == MSubDevice.class) {
            switch (baseFeatureID) {
                case ModelPackage.MSUB_DEVICE__SUB_ID:
                    return ModelPackage.REMOTE_SWITCH_C__SUB_ID;
                case ModelPackage.MSUB_DEVICE__MBRICK:
                    return ModelPackage.REMOTE_SWITCH_C__MBRICK;
                default:
                    return -1;
            }
        }
        if (baseClass == MTFConfigConsumer.class) {
            switch (baseFeatureID) {
                case ModelPackage.MTF_CONFIG_CONSUMER__TF_CONFIG:
                    return ModelPackage.REMOTE_SWITCH_C__TF_CONFIG;
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
                    return ModelPackage.REMOTE_SWITCH_C___INIT;
                case ModelPackage.MBASE_DEVICE___ENABLE:
                    return ModelPackage.REMOTE_SWITCH_C___ENABLE;
                case ModelPackage.MBASE_DEVICE___DISABLE:
                    return ModelPackage.REMOTE_SWITCH_C___DISABLE;
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
            case ModelPackage.REMOTE_SWITCH_C___INIT:
                init();
                return null;
            case ModelPackage.REMOTE_SWITCH_C___ENABLE:
                enable();
                return null;
            case ModelPackage.REMOTE_SWITCH_C___DISABLE:
                disable();
                return null;
            case ModelPackage.REMOTE_SWITCH_C___TURN_SWITCH__ONOFFVALUE:
                turnSwitch((OnOffValue) arguments.get(0));
                return null;
            case ModelPackage.REMOTE_SWITCH_C___FETCH_SWITCH_STATE:
                fetchSwitchState();
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
        result.append(" (switchState: ");
        result.append(switchState);
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
        result.append(", deviceType: ");
        result.append(deviceType);
        result.append(", systemCode: ");
        result.append(systemCode);
        result.append(", deviceCode: ");
        result.append(deviceCode);
        result.append(", repeats: ");
        result.append(repeats);
        result.append(')');
        return result.toString();
    }

} // RemoteSwitchCImpl
