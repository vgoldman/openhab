/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.homematic.internal.model;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Simple class with the JAXB mapping for a list of Homematic programs.
 *
 * @author Gerhard Riegler
 * @since 1.5.0
 */

@XmlRootElement(name = "programlist")
@XmlAccessorType(XmlAccessType.FIELD)
public class HmProgramList {

    @XmlElement(name = "program")
    private List<HmProgram> programs = new ArrayList<HmProgram>();

    /**
     * Returns all programs.
     */
    public List<HmProgram> getPrograms() {
        return programs;
    }

}
