/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.pioneeravr.internal.ipcontrolprotocol;

/**
 * This enum lists all known commands of the pioneer AV receiver.
 * It is used for configuring items to commands.
 *
 * @author Rainer Ostendorf
 * @author based on the Onkyo binding by Pauli Anttila and others
 * @since 1.4.0
 */
public enum IpControlCommandRef {

    POWER_OFF(10),
    POWER_ON(11),
    POWER_QUERY(12),

    UNMUTE(20),
    MUTE(21),
    MUTE_QUERY(22),

    VOLUME_UP(30),
    VOLUME_DOWN(31),
    VOLUME_QUERY(32),
    VOLUME_SET(33),

    SOURCE_DVD(50),
    SOURCE_BD(51),
    SOURCE_TV_SAT(52),
    SOURCE_DVR_BDR(53),
    SOURCE_VIDEO1(54),
    SOURCE_VIDEO2(55),
    SOURCE_HDMI1(56),
    SOURCE_HDMI2(57),
    SOURCE_HDMI3(58),
    SOURCE_HDMI4(59),
    SOURCE_HDMI5(60),
    SOURCE_HMG(61),
    SOURCE_IPOD(62),
    SOURCE_XMRADIO(63),
    SOURCE_CD(64),
    SOURCE_CDR_TAPE(65),
    SOURCE_TUNER(66),
    SOURCE_PHONO(67),
    SOURCE_MULTI_CH_IN(68),
    SOURCE_ADAPTER_PORT(69),
    SOURCE_SIRIUS(70),
    SOURCE_UP(71),
    SOURCE_DOWN(72),
    SOURCE_QUERY(73),
    SOURCE_SET(74),
    SOURCE_HDMI_CYCLIC(75),

    LISTENING_MODE(77),
    LISTENING_MODE_QUERY(78),

    HMG_NUMKEY(89),
    HMG_NUMKEY0(90),
    HMG_NUMKEY1(91),
    HMG_NUMKEY2(92),
    HMG_NUMKEY3(93),
    HMG_NUMKEY4(94),
    HMG_NUMKEY5(95),
    HMG_NUMKEY6(96),
    HMG_NUMKEY7(97),
    HMG_NUMKEY8(98),
    HMG_NUMKEY9(99),
    HMG_PLAY(100),
    HMG_PAUSE(101),
    HMG_PREVIOUS(102),
    HMG_NEXT(103),
    HMG_DISPLAY(104),
    HMG_STOP(105),
    HMG_UP(106),
    HMG_DOWN(107),
    HMG_RIGHT(108),
    HMG_LEFT(109),
    HMG_ENTER(110),
    HMG_RETURN(111),
    HMG_PROGRAM(112),
    HMG_CLEAR(113),
    HMG_REPEAT(114),
    HMG_RANDOM(115),
    HMG_MENU(116),
    HMG_EDIT(117),
    HMG_CLASS(118),

    TONE_ON(200),
    TONE_BYPASS(201),
    TONE_QUERY(202),
    BASS_INCREMENT(203),
    BASS_DECREMENT(204),
    BASS_QUERY(205),
    TREBLE_INCREMENT(206),
    TREBLE_DECREMENT(207),
    TREBLE_QUERY(208),

    SPEAKERS(300),
    SPEAKERS_OFF(301),
    SPEAKERS_A(302),
    SPEAKERS_B(303),
    SPEAKERS_A_B(304),

    HDMI_OUTPUT(305),
    HDMI_OUT_ALL(306),
    HDMI_OUT_1(307),
    HDMI_OUT_2(308),

    HDMI_AUDIO_AMP(350),
    HDMI_AUDIO_THROUGH(351),

    PQLS_OFF(400),
    PQLS_AUTO(401),

    ZONE2_POWER_ON(500),
    ZONE2_POWER_OFF(501),
    ZONE2_POWER_QUERY(503),
    ZONE2_INPUT(504),
    ZONE2_INPUT_DVD(506),
    ZONE2_INPUT_TV_SAT(507),
    ZONE2_INPUT_DVR_BDR(508),
    ZONE2_INPUT_VIDEO1(509),
    ZONE2_INPUT_VIDEO2(510),
    ZONE2_INPUT_HMG(511),
    ZONE2_INPUT_IPOD(512),
    ZONE2_INPUT_XMRADIO(513),
    ZONE2_INPUT_CD(514),
    ZONE2_INPUT_CDR_TAPE(515),
    ZONE2_INPUT_TUNER(516),
    ZONE2_INPUT_ADAPTER(517),
    ZONE2_INPUT_SIRIUS(518),
    ZONE2_INPUT_QUERY(519),
    ZONE2_VOLUME_UP(520),
    ZONE2_VOLUME_DOWN(521),
    ZONE2_VOLUME(522),
    ZONE2_VOLUME_QUERY(523),
    ZONE2_MUTE(524),
    ZONE2_UNMUTE(525),
    ZONE2_MUTE_QUERY(526),

    ZONE3_POWER_ON(601),
    ZONE3_POWER_OFF(604),
    ZONE3_POWER_QUERY(605),
    ZONE3_INPUT(606),
    ZONE3_INPUT_DVD(607),
    ZONE3_INPUT_TV_SAT(608),
    ZONE3_INPUT_DVR_BDR(609),
    ZONE3_INPUT_VIDEO1(610),
    ZONE3_INPUT_VIDEO2(611),
    ZONE3_INPUT_HMG(612),
    ZONE3_INPUT_IPOD(613),
    ZONE3_INPUT_XMRADIO(614),
    ZONE3_INPUT_CD(615),
    ZONE3_INPUT_CDR_TAPE(616),
    ZONE3_INPUT_TUNER(617),
    ZONE3_INPUT_ADAPTER(618),
    ZONE3_INPUT_SIRIUS(619),
    ZONE3_INPUT_QUERY(620),
    ZONE3_VOLUME_UP(621),
    ZONE3_VOLUME_DOWN(622),
    ZONE3_VOLUME(623),
    ZONE3_VOLUME_QUERY(624),
    ZONE3_MUTE(625),
    ZONE3_UNMUTE(626),
    ZONE3_MUTE_QUERY(627),

    TUNER_FREQ_INCREMENT(700),
    TUNER_FREQ_DECREMENT(701),
    TUNER_FREQ_QUERY_AM(702),
    TUNER_FREQ_QUERY_FM(703),
    TUNER_BAND(704),
    TUNER_PRESET(705),
    TUNER_CLASS(706),
    TUNER_PRESET_INCREMENT(707),
    TUNER_PRESET_DECREMENT(708),
    TUNER_PRESET_QUERY(709),

    IPOD_PLAY(800),
    IPOD_PAUSE(801),
    IPOD_STOP(802),
    IPOD_PREVIOS(803),
    IPOD_NEXT(804),
    IPOD_REV(805),
    IPOD_FWD(806),
    IPOD_REPEAT(807),
    IPOD_SHUFFLE(808),
    IPOD_DISPLAY(809),
    IPOD_CONTROL(810),
    IPOD_CURSOR_UP(811),
    IPOD_CURSOR_DOWN(812),
    IPOD_CURSOR_LEFT(813),
    IPOD_CURSOR_RIGHT(814),
    IPOD_ENTER(815),
    IPOD_RETURN(816),
    IPOD_TOP_MENU(817),
    IPOD_KEY_OFF(818),

    ADAPTER_PLAY_PAUSE(900),
    ADAPTER_PLAY(901),
    ADAPTER_PAUSE(902),
    ADAPTER_STOP(903),
    ADAPTER_PREVIOUS(904),
    ADAPTER_NEXT(905),
    ADAPTER_REV(906),
    ADAPTER_FWD(907),

    DISPLAY_INFO_QUERY(1000);

    private int command;

    private IpControlCommandRef(int command) {
        this.command = command;
    }

    public int getCommand() {
        return command;
    }

}