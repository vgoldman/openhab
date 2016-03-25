/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.tinkerforge.internal.model;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Bricklet Multi Touch Configuration</b></em>'.
 *
 * @author Theo Weiss
 * @since 1.5.0
 *        <!-- end-user-doc -->
 *
 *        <p>
 *        The following features are supported:
 *        <ul>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.BrickletMultiTouchConfiguration#getRecalibrate
 *        <em>Recalibrate</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.BrickletMultiTouchConfiguration#getSensitivity
 *        <em>Sensitivity</em>}</li>
 *        </ul>
 *        </p>
 *
 * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getBrickletMultiTouchConfiguration()
 * @model
 * @generated
 */
public interface BrickletMultiTouchConfiguration extends TFConfig {
    /**
     * Returns the value of the '<em><b>Recalibrate</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>Recalibrate</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>Recalibrate</em>' attribute.
     * @see #setRecalibrate(Boolean)
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getBrickletMultiTouchConfiguration_Recalibrate()
     * @model unique="false"
     * @generated
     */
    Boolean getRecalibrate();

    /**
     * Sets the value of the '
     * {@link org.openhab.binding.tinkerforge.internal.model.BrickletMultiTouchConfiguration#getRecalibrate
     * <em>Recalibrate</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @param value the new value of the '<em>Recalibrate</em>' attribute.
     * @see #getRecalibrate()
     * @generated
     */
    void setRecalibrate(Boolean value);

    /**
     * Returns the value of the '<em><b>Sensitivity</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>Sensitivity</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>Sensitivity</em>' attribute.
     * @see #setSensitivity(Short)
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getBrickletMultiTouchConfiguration_Sensitivity()
     * @model unique="false"
     * @generated
     */
    Short getSensitivity();

    /**
     * Sets the value of the '
     * {@link org.openhab.binding.tinkerforge.internal.model.BrickletMultiTouchConfiguration#getSensitivity
     * <em>Sensitivity</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @param value the new value of the '<em>Sensitivity</em>' attribute.
     * @see #getSensitivity()
     * @generated
     */
    void setSensitivity(Short value);

} // BrickletMultiTouchConfiguration
