/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.tinkerforge.internal.model;

import java.math.BigDecimal;

import org.openhab.binding.tinkerforge.internal.types.DecimalValue;

import com.tinkerforge.BrickletAmbientLight;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>MBricklet Ambient Light</b></em>'.
 *
 * @author Theo Weiss
 * @since 1.3.0
 *        <!-- end-user-doc -->
 *
 *        <p>
 *        The following features are supported:
 *        <ul>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.MBrickletAmbientLight#getDeviceType
 *        <em>Device Type</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.MBrickletAmbientLight#getThreshold
 *        <em>Threshold</em>}</li>
 *        </ul>
 *        </p>
 *
 * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getMBrickletAmbientLight()
 * @model superTypes=
 *        "org.openhab.binding.tinkerforge.internal.model.MDevice<org.openhab.binding.tinkerforge.internal.model.MTinkerBrickletAmbientLight> org.openhab.binding.tinkerforge.internal.model.MSensor<org.openhab.binding.tinkerforge.internal.model.MDecimalValue> org.openhab.binding.tinkerforge.internal.model.MTFConfigConsumer<org.openhab.binding.tinkerforge.internal.model.TFBaseConfiguration> org.openhab.binding.tinkerforge.internal.model.CallbackListener"
 * @generated
 */
public interface MBrickletAmbientLight extends MDevice<BrickletAmbientLight>, MSensor<DecimalValue>,
        MTFConfigConsumer<TFBaseConfiguration>, CallbackListener {
    /**
     * Returns the value of the '<em><b>Device Type</b></em>' attribute.
     * The default value is <code>"bricklet_ambient_light"</code>.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>Device Type</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>Device Type</em>' attribute.
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getMBrickletAmbientLight_DeviceType()
     * @model default="bricklet_ambient_light" unique="false" changeable="false"
     * @generated
     */
    String getDeviceType();

    /**
     * Returns the value of the '<em><b>Threshold</b></em>' attribute.
     * The default value is <code>"1"</code>.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>Threshold</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>Threshold</em>' attribute.
     * @see #setThreshold(BigDecimal)
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getMBrickletAmbientLight_Threshold()
     * @model default="1" unique="false"
     * @generated
     */
    BigDecimal getThreshold();

    /**
     * Sets the value of the '{@link org.openhab.binding.tinkerforge.internal.model.MBrickletAmbientLight#getThreshold
     * <em>Threshold</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @param value the new value of the '<em>Threshold</em>' attribute.
     * @see #getThreshold()
     * @generated
     */
    void setThreshold(BigDecimal value);

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @model annotation="http://www.eclipse.org/emf/2002/GenModel body=''"
     * @generated
     */
    @Override
    void init();

} // MBrickletAmbientLight
