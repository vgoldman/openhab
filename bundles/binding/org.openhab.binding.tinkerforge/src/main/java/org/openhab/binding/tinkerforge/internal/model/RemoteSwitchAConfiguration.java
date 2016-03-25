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
 * A representation of the model object '<em><b>Remote Switch AConfiguration</b></em>'.
 *
 * @author Theo Weiss
 * @since 1.5.0
 *        <!-- end-user-doc -->
 *
 *        <p>
 *        The following features are supported:
 *        <ul>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.RemoteSwitchAConfiguration#getHouseCode
 *        <em>House Code</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.RemoteSwitchAConfiguration#getReceiverCode
 *        <em>Receiver Code</em>}</li>
 *        <li>{@link org.openhab.binding.tinkerforge.internal.model.RemoteSwitchAConfiguration#getRepeats
 *        <em>Repeats</em>}</li>
 *        </ul>
 *        </p>
 *
 * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getRemoteSwitchAConfiguration()
 * @model
 * @generated
 */
public interface RemoteSwitchAConfiguration extends TFConfig {

    /**
     * Returns the value of the '<em><b>House Code</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>House Code</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>House Code</em>' attribute.
     * @see #setHouseCode(Short)
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getRemoteSwitchAConfiguration_HouseCode()
     * @model unique="false"
     * @generated
     */
    Short getHouseCode();

    /**
     * Sets the value of the '
     * {@link org.openhab.binding.tinkerforge.internal.model.RemoteSwitchAConfiguration#getHouseCode <em>House Code</em>
     * }' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @param value the new value of the '<em>House Code</em>' attribute.
     * @see #getHouseCode()
     * @generated
     */
    void setHouseCode(Short value);

    /**
     * Returns the value of the '<em><b>Receiver Code</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>Receiver Code</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>Receiver Code</em>' attribute.
     * @see #setReceiverCode(Short)
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getRemoteSwitchAConfiguration_ReceiverCode()
     * @model unique="false"
     * @generated
     */
    Short getReceiverCode();

    /**
     * Sets the value of the '
     * {@link org.openhab.binding.tinkerforge.internal.model.RemoteSwitchAConfiguration#getReceiverCode
     * <em>Receiver Code</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @param value the new value of the '<em>Receiver Code</em>' attribute.
     * @see #getReceiverCode()
     * @generated
     */
    void setReceiverCode(Short value);

    /**
     * Returns the value of the '<em><b>Repeats</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <p>
     * If the meaning of the '<em>Repeats</em>' attribute isn't clear,
     * there really should be more of a description here...
     * </p>
     * <!-- end-user-doc -->
     * 
     * @return the value of the '<em>Repeats</em>' attribute.
     * @see #setRepeats(Short)
     * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getRemoteSwitchAConfiguration_Repeats()
     * @model unique="false"
     * @generated
     */
    Short getRepeats();

    /**
     * Sets the value of the '
     * {@link org.openhab.binding.tinkerforge.internal.model.RemoteSwitchAConfiguration#getRepeats <em>Repeats</em>}'
     * attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @param value the new value of the '<em>Repeats</em>' attribute.
     * @see #getRepeats()
     * @generated
     */
    void setRepeats(Short value);
} // RemoteSwitchAConfiguration
