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
package org.openhab.binding.tinkerforge.internal.model;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Load Cell Configuration</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * <ul>
 * <li>{@link org.openhab.binding.tinkerforge.internal.model.LoadCellConfiguration#getMovingAverage
 * <em>Moving Average</em>}</li>
 * </ul>
 * </p>
 *
 * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getLoadCellConfiguration()
 * @model
 * @generated
 */
public interface LoadCellConfiguration extends TFBaseConfiguration {
    /**
     * Returns the value of the '<em><b>Moving Average</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>Moving Average</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>Moving Average</em>' attribute.
     * @see #setMovingAverage(short)
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getLoadCellConfiguration_MovingAverage()
     * @model unique="false"
     * @generated
     */
    short getMovingAverage();

    /**
     * Sets the value of the '
     * {@link org.openhab.binding.tinkerforge.internal.model.LoadCellConfiguration#getMovingAverage
     * <em>Moving Average</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @param value the new value of the '<em>Moving Average</em>' attribute.
     * @see #getMovingAverage()
     * @generated
     */
    void setMovingAverage(short value);

} // LoadCellConfiguration
