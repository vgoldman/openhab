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
 * A representation of the model object '<em><b>Electrode</b></em>'.
 *
 * @author Theo Weiss
 * @since 1.5.0
 *        <!-- end-user-doc -->
 *
 *        <p>
 *        The following features are supported:
 *        <ul>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.Electrode#getDeviceType <em>Device Type</em>}</li>
 *        </ul>
 *        </p>
 *
 * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getElectrode()
 * @model
 * @generated
 */
public interface Electrode extends MultiTouchDevice {
    /**
     * Returns the value of the '<em><b>Device Type</b></em>' attribute.
     * The default value is <code>"electrode"</code>.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>Device Type</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>Device Type</em>' attribute.
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getElectrode_DeviceType()
     * @model default="electrode" unique="false" changeable="false"
     * @generated
     */
    String getDeviceType();

} // Electrode
