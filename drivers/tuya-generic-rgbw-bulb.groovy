/**
 * Tuya Generic RGBW Bulb Driver for Hubitat
 * Version: 1.0.3
 *
 * Original Copyright 2023-2024 Ivar Holand
 * Modified 2025-06-15 by qwerk to add Protocol 3.5 support and connection reliability fixes
 * Last updated: 2025-06-15 13:38:36 UTC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import groovy.transform.Field
import hubitat.device.HubAction
import hubitat.device.Protocol
import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.InvalidKeyException

metadata {
    definition(name: "Tuya Generic RGBW Bulb",
            namespace: "qwerk",
            author: "qwerk",
            importUrl: "https://raw.githubusercontent.com/qwerk/tuya-rgbw-hubitat-driver/main/drivers/tuya-generic-rgbw-bulb.groovy",
            singleThreaded: true) {
        capability "Actuator"
        capability "Bulb"
        capability "ColorTemperature"
        capability "ColorControl"
        capability "ColorMode"
        capability "Refresh"
        capability "LevelPreset"
        capability "SwitchLevel"
        capability "Switch"
        capability "LightEffects"
        capability "PresenceSensor"

        command "status"
        command "SendCustomDataToDevice", [[name:"endpoint*", type:"NUMBER", description:"To which endpoint(dps) do you want the data to be sent"], [name:"data*", type:"STRING", description:"The data to be sent"]]
        command "Disconnect"
        command "SendCustomJSONObject", [[name:"jsonPayload*", type: "STRING", description:"Format: {\"20\":true, \"22\":250, \"21\":\"white\"}"]]

        attribute "rawMessage", "String"
    }
}

preferences {
    section("Tuya Device Config") {
        input "ipaddress", "text", title: "Device IP:", required: true, description: "<small>Tuya device local IP address. Found by using tools like tinytuya. Tip: configure a fixed IP address for your tuya device.</small>"
        input "devId", "text", title: "Device ID:", required: true, description: "<small>Unique tuya device ID. Found by using tools like tinytuya.</small>"
        input "localKey", "text", title: "Device local key:", required: true, description: "<small>The local key used for encrypted communication between HE and the tuya Device. Found by using tools like tinytuya.</small>"
        input name: "logEnable", type: "bool", title: "Enable <u>debug</u> logging", defaultValue: true, description: "<small>If issues are experienced it might help to turn on debug logging and see the debug output for troubleshooting.</small>"
        input name: "logTrace", type: "bool", title: "Enable driver level <u>trace</u> logging", defaultValue: true, description: "<small>For debugging scenes and automations it could be helpful to follow the trace log.</small>"
        input "tuyaProtVersion", "enum", title: "Select tuya protocol version: ", required: true, defaultValue: 34, options: [31: "3.1", 33: "3.3", 34: "3.4", 35: "3.5"], description: "<small>Select the correct protocol version for your device.</small>"
        input name: "poll_interval", type: "enum", title: "Configure poll interval:", defaultValue: 0, options: [0: "No polling", 1:"Every 1 second", 2:"Every 2 second", 3: "Every 3 second", 5: "Every 5 seconds", 10: "Every 10 seconds", 30: "Every 30 seconds", 60: "Every 1 minute", 300: "Every 5 minutes", 600: "Every 10 minutes"], description: "<small>Set how often to poll the device for status updates.</small>"
        input name: "autoReconnect", type: "bool", title: "Auto reconnect on socket close", defaultValue: true, description: "<small>A communication channel is kept open between HE and the tuya device. Every time the connection fails, it will automatically reconnect.</small>"
        input name: "heartBeatMethod", type: "bool", title: "Use heart beat method to keep connection alive", defaultValue: true, description: "<small>Use a heart beat to keep the connection alive, i.e. a message every 20 seconds.</small>"
    }
    section("Other") {
        input name: "color_mode", type: "enum", title: "Configure bulb color mode:", defaultValue: "hsv", options: ["hsv": "HSV (native Hubitat)", "hsl": "HSL"]
    }
}

@Field static Map frameChecksumSize = [
    "31": 4,
    "33": 4,
    "34": 32,
    "35": 32  // Protocol 3.5 uses same checksum size as 3.4
]

@Field static Map frameTypes = [
    3:  "KEY_START",
    4:  "KEY_RESP",
    5:  "KEY_FINAL",
    7:  "CONTROL",
    8:  "STATUS_RESP",
    9:  "HEART_BEAT",
    10: "DP_QUERY",
    13: "CONTROL_NEW",
    16: "DP_QUERY_NEW"
]

@Field static String fCommand = ""
@Field static Map fMessage = [:]

def installed() {
    updated()
}

def updated() {
    log.info "updated..."
    log.warn "debug logging is: ${logEnable == true}"
    state.clear()
    if (logEnable) runIn(1800, logsOff)
    if (logTrace) runIn(1800, logsOff)

    _updatedTuya()

    // Configure poll interval
    if (poll_interval.toInteger() != null) {
        if (poll_interval.toInteger() == 0) {
            unschedule(status)
        } else if (poll_interval.toInteger() < 60) {
            schedule("*/${poll_interval} * * ? * *", status)
        } else if (poll_interval.toInteger() < 60*60) {
            minutes = poll_interval.toInteger()/60
            if(logEnable) log.debug "Setting schedule to pull every ${minutes} minutes"
            schedule("0 */${minutes} * ? * *", status)
        }
        status()
    } else {
        status()
    }

    sendEvent(name: "switch", value: "off")
}

def logsOff() {
    log.warn "debug and trace logging disabled..."
    device.updateSetting("logEnable", [value: "false", type: "bool"])
    device.updateSetting("logTrace", [value: "false", type: "bool"])
}

def setColorTemperature(colortemperature, level=null, transitionTime=null) {
    if (logTrace) log.trace("setColorTemperature($colortemperature, $level, $transitionTime)")
    def setMap = [:]

    setMap[21] = "white"

    Integer bulb_ct_setting = (colortemperature/3.8) - (2700/3.8)

    if (bulb_ct_setting < 0) bulb_ct_setting = 0
    if (bulb_ct_setting > 1000) bulb_ct_setting = 1000

    setMap[23] = bulb_ct_setting

    if (level != null) {
        if (level > 100) level = 100
        if (level < 0) level = 0

        setMap[22] = level*10
    }

    if (level == 0) {
        off()
    } else {
        on()
    }

    state.statePayload += setMap
    runInMillis(250, 'sendSetMessage')
}

def setColor(colormap) {
    if (logTrace) log.trace("setColor($colormap)")

    def setMap = [:]
    setMap[21] = "colour"

    if (logEnable) log.debug(colormap)

    if (color_mode == "hsl") {
        colormap = hsvToHsl(colormap.hue, colormap.saturation, colormap.level)
    } else if (color_mode == "hsv") {
        colormap = colormap
    }

    Integer bHue = colormap.hue * 3.6
    Integer bSat = colormap.saturation*10
    Integer bValue = colormap.level*10

    def setting = sprintf("%04x%04x%04x", bHue, bSat, bValue)
    setMap[24] = setting

    if (bHue == 0 && bSat == 0 && bValue == 0) {
        off()
    } else {
        on()
    }

    state.statePayload += setMap
    runInMillis(250, 'sendSetMessage')
}

def setHue(hue) {
    if (logTrace) log.trace("setHue($hue)")
    def currentState = device.currentState("color")?.value
    def colormap = [:]
    
    if (currentState) {
        colormap = currentState
        colormap.hue = hue
    } else {
        colormap.hue = hue
        colormap.saturation = 100
        colormap.level = 100
    }
    
    setColor(colormap)
}

def setSaturation(saturation) {
    if (logTrace) log.trace("setSaturation($saturation)")
    def currentState = device.currentState("color")?.value
    def colormap = [:]
    
    if (currentState) {
        colormap = currentState
        colormap.saturation = saturation
    } else {
        colormap.hue = 0
        colormap.saturation = saturation
        colormap.level = 100
    }
    
    setColor(colormap)
}

def setEffect(effectnumber) {
    if (logTrace) log.trace("setEffect($effectnumber)")

    state.effectnumber = effectnumber.intValue()

    def lightEffects = [
        0 : "000e0d0000000000000000c803e8", // Good night
        1 : "010e0d0000000000000003e803e8", // Reading
        2 : "020e0d0000000000000003e803e8", // Working
        3 : "030e0d0000000000000001f403e8"  // Leisure
    ]

    def setMap = [:]
    setMap[21] = "scene"
    setMap[25] = lightEffects[effectnumber.intValue()]

    on()
    state.statePayload += setMap
    runInMillis(250, 'sendSetMessage')
}

def setNextEffect() {
    if (logTrace) log.trace("setNextEffect()")
    
    def temp = state.effectnumber
    if (temp == null) temp = 0
    temp = temp + 1
    if (temp > 6) temp = 0
    
    setEffect(temp)
}

def setPreviousEffect() {
    if (logTrace) log.trace("setPreviousEffect()")
    
    def temp = state.effectnumber
    if (temp == null) temp = 0
    temp = temp - 1
    if (temp < 0) temp = 6
    
    setEffect(temp)
}

def on() {
    if (logTrace) log.trace("on()")
    state.statePayload[20] = true
    runInMillis(250, 'sendSetMessage')
}

def off() {
    if (logTrace) log.trace("off()")
    state.statePayload[20] = false
    runInMillis(250, 'sendSetMessage')
}

def refresh() {
    if (logTrace) log.trace("refresh()")
    status()
}

def status() {
    if (logTrace) log.trace("status()")
    send("status", [:])
}

def heartbeat() {
    if(logTrace) log.trace("heartbeat()")
    send("status", [:])
}

def sendSetMessage() {
    if (logTrace) log.trace("sendSetMessage() // current state.statePayload = $state.statePayload)")
    send("set", state.statePayload)
    state.statePayload = [:]
}

def hslToHsv(hue, saturation, level) {
    if (logEnable) log.debug("HSL to HSV: ${hue}, ${saturation}, ${level}")

    // Convert percentages to decimals
    def s = saturation / 100.0
    def l = level / 100.0

    // Calculate value
    def v = l + s * Math.min(l, 1 - l)
    
    // Calculate saturation for HSV
    def newS = 0.0
    if (v != 0) {
        newS = 2 * (1 - l/v)
    }

    // Ensure values are within bounds
    v = Math.min(Math.max(v, 0), 1)
    newS = Math.min(Math.max(newS, 0), 1)

    // Create return map with calculated values
    def retMap = [
        "hue": hue,
        "saturation": (newS * 100).round(0),
        "value": (v * 100).round(0)
    ]
    
    if (logEnable) log.debug "HSL to HSV conversion result: $retMap"
    return retMap
}

def hsvToHsl(hue, saturation, value) {
    if (logEnable) log.debug("HSV to HSL: ${hue}, ${saturation}, ${value}")

    // Convert percentages to decimals
    def s = saturation / 100.0
    def v = value / 100.0

    // Calculate lightness
    def l = v * (1 - s/2)
    
    // Calculate saturation for HSL
    def newS = 0.0
    if (l > 0 && l < 1) {
        newS = (v - l) / Math.min(l, 1 - l)
    }

    // Ensure values are within bounds
    l = Math.min(Math.max(l, 0), 1)
    newS = Math.min(Math.max(newS, 0), 1)

    // Create return map with calculated values
    def retMap = [
        "hue": hue,
        "saturation": (newS * 100).round(0),
        "level": (l * 100).round(0)
    ]
    
    if (logEnable) log.debug "HSV to HSL conversion result: $retMap"
    return retMap
}

def send(String command, Map message=null) {
    boolean sessionState = state.HaveSession

    if (sessionState == false) {
        if(logEnable) log.debug "No session, creating new session"
        sessionState = get_session(settings.tuyaProtVersion)
    }

    if (sessionState) {
        socket_write(generate_payload(command, message))
    }

    fCommand = command
    fMessage = message

    state.HaveSession = sessionState

    runInMillis(1000, sendTimeout)
}

def sendAll() {
    if (fCommand != "") {
        send(fCommand, fMessage)
    }
}

def sendTimeout() {
    if (state.retry > 0) {
        if (logEnable) log.warn "No response from device, retrying..."
        state.retry = state.retry - 1
        // Add delay between retries
        runIn(2, sendAll)  // Added 2-second delay between retries
    } else {
        log.error "No answer from device after 5 retries"
        socket_close()
        // Attempt to re-establish session
        runIn(5, retrySession)
    }
}

def socket_connect() {
    if (logEnable) log.debug "Socket connect: $settings.ipaddress at port: 6668"

    boolean returnStatus = true

    try {
        interfaces.rawSocket.connect(settings.ipaddress, 6668, byteInterface: true, readDelay: 500)  // Increased readDelay
        returnStatus = true
        
        // Add connection verification
        if (interfaces.rawSocket.isConnected()) {
            if (logEnable) log.debug "Socket connected successfully"
        } else {
            log.error "Socket connection failed"
            returnStatus = false
        }
    } catch (java.net.NoRouteToHostException ex) {
        log.error "$ex - Can't connect to device, make sure correct IP address"
        returnStatus = false
    } catch (java.net.SocketTimeoutException ex) {
        log.error "$ex - Can't connect to device, make sure correct IP address"
        returnStatus = false
    } catch (e) {
        log.error "Error $e"
        returnStatus = false
    }
    return returnStatus
}

def socket_write(byte[] message) {
    String msg = hubitat.helper.HexUtils.byteArrayToHexString(message)
    if (logEnable) log.debug "Socket: write - " + settings.ipaddress + ":" + 6668 + " msg: " + msg

    try {
        interfaces.rawSocket.sendMessage(msg)
    } catch (e) {
        log.error "Error sending data to device: $e"
        socket_close()
        runIn(5, retrySession)
    }
}

def socket_close(boolean willTryToReconnect=false) {
    if(logEnable) log.debug "Socket: close"

    unschedule(sendTimeout)

    if (willTryToReconnect == false) {
        sendEvent(name: "presence", value: "not present")
    }

    state.session_step = "step1"
    state.HaveSession = false
    state.sessionKey = null

    try {
        interfaces.rawSocket.close()
    } catch (e) {
        log.error "Could not close socket: $e"
    }
}

def _updatedTuya() {
    state.statePayload = [:]
    state.HaveSession = false
    state.session_step = "step1"
    state.retry = 5
    state.Msgseq = 1
    state.sessionRetries = 0
}

Short getNewMessageSequence() {
    if (state.Msgseq == null) state.Msgseq = 0
    state.Msgseq = state.Msgseq + 1
    return state.Msgseq
}

byte[] getRealLocalKey() {
    byte[] staticLocalKey = localKey.replaceAll('&lt;', '<').getBytes("UTF-8")
    device.updateSetting("localKey", [value: localKey.replaceAll('&lt;', '<'), type: "text"])
    return staticLocalKey
}

def generateKeyStartMessage(String nonce, byte[] key, Short seqno) {
    if (logTrace) log.trace("generateKeyStartMessage($nonce, $key, $seqno)")
    
    ByteArrayOutputStream buffer = new ByteArrayOutputStream()
    // Prefix bytes
    buffer.write(0x00)
    buffer.write(0x00)
    buffer.write(0x55)
    buffer.write(0xAA)
    buffer.write(0x00)
    // Sequence number
    buffer.write(seqno & 0xFF)
    buffer.write((seqno >> 8) & 0xFF)
    // Command byte (3 for KEY_START)
    buffer.write(0x03)
    // Length placeholder
    buffer.write(0x00)
    buffer.write(0x00)
    buffer.write(0x00)
    buffer.write(0x00)
    
    // Calculate and write HMAC
    def hmac = calculateHmac(nonce.getBytes("UTF-8"), key)
    buffer.write(hmac)
    
    // Suffix bytes
    buffer.write(0x00)
    buffer.write(0x00)
    buffer.write(0xAA)
    buffer.write(0x55)
    
    byte[] result = buffer.toByteArray()
    
    // Update length
    int payloadLength = result.length - 16
    result[9] = (payloadLength & 0xFF)
    result[10] = ((payloadLength >> 8) & 0xFF)
    result[11] = ((payloadLength >> 16) & 0xFF)
    result[12] = ((payloadLength >> 24) & 0xFF)
    
    return result
}

def get_session(String tuyaVersion) {
    if (logTrace) log.trace("get_session($tuyaVersion)")
    
    def returnValue = false
    
    if (state.session_step == "step1") {
        try {
            // Generate random 16-byte local key for session
            def randomBytes = new byte[16]
            new Random().nextBytes(randomBytes)
            state.LocalNonce = hubitat.helper.HexUtils.byteArrayToHexString(randomBytes)
            
            if (socket_connect()) {
                // Send key exchange start message
                byte[] keyStartMessage = generateKeyStartMessage(state.LocalNonce, getRealLocalKey(), getNewMessageSequence())
                socket_write(keyStartMessage)
                state.session_step = "step2"
                state.lastSessionAttempt = now()  // Track session attempt time
                if (logEnable) log.debug "Session initialization started"
                returnValue = true  // Return true if socket connection successful
            } else {
                log.error "Failed to connect socket"
            }
        } catch (Exception e) {
            log.error "Error in get_session: $e"
            socket_close()
        }
    }
    
    // Set session timeout with longer duration
    runIn(10, get_session_timeout)  // Increased from 5 to 10 seconds
    return returnValue
}

def get_session_timeout() {
    if (logTrace) log.trace("get_session_timeout()")
    
    if (state.HaveSession == false) {
        def timeSinceLastAttempt = now() - (state.lastSessionAttempt ?: 0)
        if (timeSinceLastAttempt > 10000) {  // 10 seconds
            log.error "Session creation timed out"
            socket_close()
            // Add retry mechanism
            if (state.sessionRetries == null) state.sessionRetries = 0
            if (state.sessionRetries < 3) {
                state.sessionRetries = state.sessionRetries + 1
                runIn(5, retrySession)
            } else {
                log.error "Failed to establish session after 3 retries"
                state.sessionRetries = 0
            }
        }
    }
}

def retrySession() {
    if (logEnable) log.debug "Retrying session establishment"
    state.session_step = "step1"
    state.HaveSession = false
    send("status", [:])
}

def parse(String message) {
    if (logTrace) log.trace("parse()")
    
    List results = []
    
    try {
        // Unschedule timeout since we got a response
        unschedule(sendTimeout)
        state.retry = 5

        String start = "000055AA"
        List<Integer> startIndexes = []
        
        // Find all message starts
        int index = 0
        int location = 0
        while (index != -1 && location < message.length()) {
            index = message.indexOf(start, location)
            if (index != -1) {
                startIndexes.add(index/2)
                location = index + start.length()
            }
        }
        
        if (logEnable) log.debug "Found message starts at: $startIndexes"
        
        byte[] incomingData = hubitat.helper.HexUtils.hexStringToByteArray(message)
        
        // Process each message
        startIndexes.each { Integer startIdx ->
            try {
                Map result = processMessage(incomingData, startIdx)
                if (result && !result.isEmpty()) {
                    results.add(result)
                }
            } catch (Exception e) {
                log.error "Error processing message at index $startIdx: $e"
            }
        }
    } catch (Exception e) {
        log.error "Error parsing message: $e"
    }
    
    // Process results
    results.each { Map status_object ->
        processStatusObject(status_object)
    }
    
    return results
}

def processMessage(byte[] data, Integer startIndex) {
    Map resultMap = [:]
    
    try {
        int frameType = Byte.toUnsignedInt(data[startIndex + 11])
        int frameLength = Byte.toUnsignedInt(data[startIndex + 15])
        
        if (logEnable) log.debug "Processing frame type: $frameType, length: $frameLength"
        
        switch(frameType) {
            case 4: // KEY_RESP
                if (state.session_step == "step2") {
                    def resp = decodeIncomingKeyResponse(hubitat.helper.HexUtils.byteArrayToHexString(data))
                    if (resp) {
                        socket_write(resp[0])
                        state.session_step = "step3"
                    } else {
                        log.error "Failed to decode key response"
                        socket_close()
                    }
                }
                break
                
            case 5: // KEY_FINAL
                if (state.session_step == "step3") {
                    state.HaveSession = true
                    if (settings.heartBeatMethod == true) {
                        schedule("0/20 * * ? * *", heartbeat)
                    }
                }
                break
                
            case 8: // STATUS_RESP
                try {
                    String decrypted = decryptPayload(data, getRealLocalKey(), startIndex + 20, frameLength - 8)
                    def jsonSlurper = new groovy.json.JsonSlurper()
                    resultMap = jsonSlurper.parseText(decrypted)
                } catch (e) {
                    log.error "Error processing status response: $e"
                }
                break
                
            default:
                if (logEnable) log.debug "Unhandled frame type: $frameType"
                break
        }
    } catch (Exception e) {
        log.error "Error processing message: $e"
    }
    
    return resultMap
}

def processStatusObject(Map status_object) {
    if (!status_object?.dps) return
    
    if (status_object.dps.containsKey("20")) {
        sendEvent(name: "switch", value: status_object.dps["20"] ? "on" : "off")
    }
    if (status_object.dps.containsKey("21")) {
        sendEvent(name: "colorMode", value: status_object.dps["21"] == "white" ? "CT" : 
                                          status_object.dps["21"] == "colour" ? "RGB" : "EFFECTS")
    }
    if (status_object.dps.containsKey("22")) {
        sendEvent(name: "presetLevel", value: status_object.dps["22"]/10)
        sendEvent(name: "level", value: status_object.dps["22"]/10)
    }
    if (status_object.dps.containsKey("23")) {
        Integer colortemperature = (status_object.dps["23"] + (2700/3.8))*3.8
        sendEvent(name: "colorTemperature", value: colortemperature)
    }
    if (status_object.dps.containsKey("24")) {
        def hueStr = status_object.dps["24"].substring(0,4)
        Float hue_fl = Integer.parseInt(hueStr, 16)/3.6
        Integer hue = hue_fl.round(0)

        def satStr = status_object.dps["24"].substring(5,8)
        def sat = Integer.parseInt(satStr, 16)/10

        def levelStr = status_object.dps["24"].substring(9,12)
        def level = Integer.parseInt(levelStr, 16)/10

        def colormap = color_mode == "hsl" ? [hue: hue, saturation: sat, level: level] : hslToHsv(hue, sat, level)

        sendEvent(name: "hue", value: colormap.hue)
        sendEvent(name: "saturation", value: colormap.saturation)
        sendEvent(name: "level", value: colormap.value ?: colormap.level)
    }
}

private byte[] calculateHmac(byte[] nonce, byte[] key) {
    try {
        Mac hmac = Mac.getInstance("HmacSHA256")
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256")
        hmac.init(secretKey)
        return hmac.doFinal(nonce)
    } catch (Exception e) {
        log.error "Error calculating HMAC: $e"
        return null
    }
}

def decodeIncomingKeyResponse(String message) {
    if (logTrace) log.trace("decodeIncomingKeyResponse($message)")
    
    try {
        byte[] remoteNonce = message.substring(0, 16).getBytes("UTF-8")
        
        ByteArrayOutputStream buffer = new ByteArrayOutputStream()
        buffer.write(0x00) // prefix
        buffer.write(0x00) // prefix
        buffer.write(0x55) // prefix
        buffer.write(0xAA) // prefix
        buffer.write(0x00) // version
        buffer.write(getNewMessageSequence() & 0xFF)
        buffer.write((getNewMessageSequence() >> 8) & 0xFF)
        buffer.write(0x05) // KEY_FINAL command
        buffer.write(0x00) // length placeholder
        buffer.write(0x00)
        buffer.write(0x00)
        buffer.write(0x00)
        
        def hmac = calculateHmac(remoteNonce, getRealLocalKey())
        buffer.write(hmac)
        
        buffer.write(0x00)
        buffer.write(0x00)
        buffer.write(0xAA)
        buffer.write(0x55)
        
        byte[] result = buffer.toByteArray()
        
        // Update length
        int payloadLength = result.length - 16
        result[9] = (payloadLength & 0xFF)
        result[10] = ((payloadLength >> 8) & 0xFF)
        result[11] = ((payloadLength >> 16) & 0xFF)
        result[12] = ((payloadLength >> 24) & 0xFF)
        
        return [result, remoteNonce]
    } catch (Exception e) {
        log.error "Error decoding key response: $e"
        return null
    }
}

def decryptPayload(byte[] data, byte[] key, int offset, int length) {
    try {
        // Use AES decryption in ECB mode
        Cipher cipher = Cipher
      
