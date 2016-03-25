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
 * A representation of the model object '<em><b>OHTF Sub Device Admin Device</b></em>'.
 *
 * @author Theo Weiss
 * @since 1.5.0
 *        <!-- end-user-doc -->
 *
 *
 * @see org.openhab.binding.tinkerforge.internal.model.ModelPackage#getOHTFSubDeviceAdminDevice()
 * @model IDSBounds="org.openhab.binding.tinkerforge.internal.model.Enum"
 * @generated
 */
public interface OHTFSubDeviceAdminDevice<TFC extends TFConfig, IDS extends Enum> extends OHTFDevice<TFC, IDS> {
    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * 
     * @model unique="false" subIdUnique="false"
     *        annotation="http://www.eclipse.org/emf/2002/GenModel body='return true;'"
     * @generated
     */
    @Override
    boolean isValidSubId(String subId);

} // OHTFSubDeviceAdminDevice
