from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP

class TimeStampField(FixedPointField):
    def __init__(self, name, default):
        FixedPointField.__init__(self, name, default, 80, 32)
    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        val = self.i2h(pkt,val)
        return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(val))
    def any2i(self, pkt, val):
        if type(val) is str:
            return int(time.mktime(time.strptime(val)))
        return FixedPointField.any2i(self,pkt,val)
    def i2m(self, pkt, val):
        if val is None:
            val = FixedPointField.any2i(self, pkt, time.time())
        return FixedPointField.i2m(self, pkt, val) 
        
class PortIdentityField(Field):
    def __init__(self, name, default):
         Field.__init__(self, name, default, "10s")
       
class ClockIdentityField(Field):
    def __init__(self, name, default):
         Field.__init__(self, name, default, "8s")
       
class PtpHdr(Packet):
    name = "PtpHdr"
    fields_desc = [ 
        BitField('transportSpecific', 0, 4),
        BitEnumField('messageType', 0, 4,
                     { 0: 'Sync', #
                       1: 'Delay_Req', #
                       2: 'Pdelay_Req',
                       3: 'Pdelay_Resp',
                       4: 'Reserved',
                       5: 'Reserved',
                       6: 'Reserved',
                       7: 'Reserved',
                       8: 'Follow_Up', #
                       9: 'Delay_Resp', #
                       10: 'Pdelay_Resp_Follow_Up',
                       11: 'Announce', #
                       12: 'Signaling',
                       13: 'Management',
                       14: 'Reserved',
                       15: 'Reserved'}),
        BitField('reserved1', 0, 4),
        BitField('versionPTP', 2, 4),
        ShortField('messageLength',None),
        ByteField('domainNumber',0),
        ByteField('reserved2',0),
        FlagsField('flagField',0x0200,16,[ "leap61",
                                      "leap59",
                                      "currentUtcOffsetValid",
                                      "ptpTimescale",
                                      "timeTraceable",
                                      "frequencyTraceable",
                                      "",
                                      "",
                                      "alternateMasterFlag",
                                      "twoStepFlag",
                                      "unicastFlag",
                                      "",
                                      "",
                                      "PTP profile Specific 1",
                                      "PTP profile Specific 2",
                                      "reserved"]),
        LongField('correctionField',0),
        IntField('reserved3',0),
        PortIdentityField('sourcePortIdentity','\0\0\0\0\0\0\0\0\0\0'),
        ShortField('sequenceId',0),
        ByteField('controlField',0),
        ByteField('logMessageInterval', 1)
        ]    
    def post_build(self, p, pay):
        l = len(p+pay)
        p = p[:2] + struct.pack("!H", l) + p[4:]
        print 'ML', l
        return p+pay

class PtpEventMsg(Packet):
    name = "PtpEventMsg"
    fields_desc = [ 
        BitField('transportSpecific', 0, 4),
        BitEnumField('messageType', 0, 4,
                     { 0: 'Sync', #
                       1: 'Delay_Req', #
                       2: 'Pdelay_Req',
                       3: 'Pdelay_Resp',
                       4: 'Reserved',
                       5: 'Reserved',
                       6: 'Reserved',
                       7: 'Reserved',
                       8: 'Follow_Up', #
                       9: 'Delay_Resp', #
                       10: 'Pdelay_Resp_Follow_Up',
                       11: 'Announce', #
                       12: 'Signaling',
                       13: 'Management',
                       14: 'Reserved',
                       15: 'Reserved'}),
        BitField('reserved1', 0, 4),
        BitField('versionPTP', 2, 4),
        ShortField('messageLength',None),
        ByteField('domainNumber',0),
        ByteField('reserved2',0),
        FlagsField('flagField',0x0200,16,[ "leap61",
                                      "leap59",
                                      "currentUtcOffsetValid",
                                      "ptpTimescale",
                                      "timeTraceable",
                                      "frequencyTraceable",
                                      "",
                                      "",
                                      "alternateMasterFlag",
                                      "twoStepFlag",
                                      "unicastFlag",
                                      "",
                                      "",
                                      "PTP profile Specific 1",
                                      "PTP profile Specific 2",
                                      "reserved"]),
        LongField('correctionField',0),
        IntField('reserved3',0),
        PortIdentityField('sourcePortIdentity','\0\0\0\0\0\0\0\0\0\0'),
        ShortField('sequenceId',0),
        ByteField('controlField',0),
        ByteField('logMessageInterval', 1)
        ]    
    def post_build(self, p, pay):
        l = len(p+pay)
        p = p[:2] + struct.pack("!H", l) + p[4:]
        print 'ML', l
        return p+pay
    def guess_payload_class(self, payload):
        if self.messageType == 0:
            return PtpSync
        elif self.messageType == 1:
            return PtpDelayReq
        else:
            return Packet.guess_payload_class(self, payload)  

class PtpGeneralMsg(Packet):
    name = "PtpGeneralMsg"
    fields_desc = [ 
        BitField('transportSpecific', 0, 4),
        BitEnumField('messageType', 0, 4,
                     { 0: 'Sync', #
                       1: 'Delay_Req', #
                       2: 'Pdelay_Req',
                       3: 'Pdelay_Resp',
                       4: 'Reserved',
                       5: 'Reserved',
                       6: 'Reserved',
                       7: 'Reserved',
                       8: 'Follow_Up', #
                       9: 'Delay_Resp', #
                       10: 'Pdelay_Resp_Follow_Up',
                       11: 'Announce', #
                       12: 'Signaling',
                       13: 'Management',
                       14: 'Reserved',
                       15: 'Reserved'}),
        BitField('reserved1', 0, 4),
        BitField('versionPTP', 2, 4),
        ShortField('messageLength',None),
        ByteField('domainNumber',0),
        ByteField('reserved2',0),
        FlagsField('flagField',0x0200,16,[ "leap61",
                                      "leap59",
                                      "currentUtcOffsetValid",
                                      "ptpTimescale",
                                      "timeTraceable",
                                      "frequencyTraceable",
                                      "",
                                      "",
                                      "alternateMasterFlag",
                                      "twoStepFlag",
                                      "unicastFlag",
                                      "",
                                      "",
                                      "PTP profile Specific 1",
                                      "PTP profile Specific 2",
                                      "reserved"]),
        LongField('correctionField',0),
        IntField('reserved3',0),
        PortIdentityField('sourcePortIdentity','\0\0\0\0\0\0\0\0\0\0'),
        ShortField('sequenceId',0),
        ByteField('controlField',0),
        ByteField('logMessageInterval', 1)
        ]    
        
    def post_build(self, p, pay):
        l = len(p+pay)
        p = p[0:2]  + struct.pack("!H", l) +  p[4:]
        return p+pay

        
        
    def guess_payload_class(self, payload):
        if self.messageType == 2:
            return PtpPDelayReq
        elif self.messageType == 3:
            return PtpPDelayResp
        elif self.messageType == 8:
            return PtpFollowUp
        elif self.messageType == 9:
            return PtpDelayResp
        elif self.messageType == 0xA:
            return Packet.guess_payload_class(self, payload)
        elif self.messageType == 0xB:
            return PtpAnnounce
        elif self.messageType == 0xC:
            return Packet.guess_payload_class(self, payload)
        elif self.messageType == 0xD:
            return PtpManagement
        else:
            return Packet.guess_payload_class(self, payload)

class PtpAnnounce(Packet):
    name = 'PtpAnnounce'
    fields_desc = [
        TimeStampField('originTimestamp',0),
        ShortField('currentUtcOffset', 0),
        ByteField('reserved', 0),
        ByteField('grandmasterPriority1', 128),
        IntField('grandmasterClockQuality', 0xF8FEFFFF),
        ByteField('grandmasterPriority2', 128),
        ClockIdentityField('grandmasterIdentity', '\0\0\0\0\0\0\0\0'),
        ShortField('stepsRemoved', 0),
        ByteField('timeSource', 0xA0)
        ]

class PtpSync(Packet):
    name = 'PtpSync'
    fields_desc = [
#        PtpEventMsg,
        TimeStampField('originTimestamp',0)
        ]

class PtpFollowUp(Packet):
    name = 'PtpFollowUp'
    fields_desc = [
#       PtpGeneralMsg,
        TimeStampField('preciseOriginTimestamp',0)
        ]
    def post_build(self, p, pay):
        l = len(p)
        p = struct.pack("B", 0x8) + p[1:2]  + struct.pack("!H", l) +  p[4:32] + struct.pack("B", 2) + p[33:]
        return p+pay

class PtpDelayReq(Packet):
    name = 'PtpDelayReq'
    fields_desc = [
        PtpEventMsg,
        TimeStampField('originTimestamp',0)
        ]
    def post_build(self, p, pay):
        l = len(p)
        p = struct.pack("B", 0x1) + p[1:2]  + struct.pack("!H", l) +  p[4:32] + struct.pack("B", 1) + p[33:]
        return p+pay

class PtpDelayResp(Packet):
    name = 'PtpDelayResp'
    fields_desc = [
#        PtpGeneralMsg,
        TimeStampField('receiveTimestamp',0),
        PortIdentityField('requestingPortIdentity','\0\0\0\0\0\0\0\0\0\0')
        ]
    def post_build(self, p, pay):
        l = len(p)
        p = struct.pack("B", 0x9) + p[1:2]  + struct.pack("!H", l) +  p[4:32] + struct.pack("B", 3) + p[33:]
        return p+pay

class PtpPDelayReq(Packet):
    name = 'PtpPDelayReq'
    fields_desc = [
#        PtpGeneralMsg,
        TimeStampField('originTimestamp',0)
    ]
    def post_build(self, p, pay):
        l = len(p)
        p = struct.pack("B", 0x2) + p[1:2]  + struct.pack("!H", l) +  p[4:32] + struct.pack("B", 5) + p[33:]
        return p+pay

class PtpPDelayResp(Packet):
    name = 'PtpPDelayResp'
    fields_desc = [
#       PtpGeneralMsg,
        TimeStampField('requestReceiptTimestamp',0),
        PortIdentityField('requestingPortIdentity','\0\0\0\0\0\0\0\0\0\0')
        ]
    def post_build(self, p, pay):
        l = len(p)
        p = struct.pack("B", 0x3) + p[1:2]  + struct.pack("!H", l) +  p[4:32] + struct.pack("B", 5) + p[33:]
        return p+pay

class PtpTlv(Packet):
    name = 'PtpTlv'
    fields_desc = [
        ShortEnumField('tlvType', 0x0000, {0x0000:"Reserved1",
                                      0x0001:"MANAGEMENT",
                                      0x0002:"MANAGEMENT_ERROR_STATUS",
                                      0x0003:"ORGANIZATION_EXTENSION",
                                      0x0004:"REQUEST_UNICAST_TRANSMISSION",
                                      0x0005:"GRANT_UNICAST_TRANSMISSION",
                                      0x0006:"CANCEL_UNICAST_TRANSMISSION",
                                      0x0007:"ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION",
                                      0x0008:"PATH_TRACE",
                                      0x0009:"ALTERNATE_TIME_OFFSET_INDICATOR",
                                      0x2000:"AUTHENTICATION",
                                      0x2001:"AUTHENTICATION_CHALLENGE",
                                      0x2002:"SECURITY_ASSOCIATION_UPDATE",
                                      0x2003:"CUM_FREQ_SCALE_FACTOR_OFFSET"}),
        ShortField('lengthField',0)
        ]
    def post_build(self, p, pay):
        if (pay != None):
            l = len(pay)
        else:
            l = 0
        p = p[:2] + struct.pack("!H", l) + p[4:]
        return p+pay

class PtpManagement(Packet):
    name = 'PtpManagement'
    fields_desc = [
        PortIdentityField('targetPortIdentity','\0\0\0\0\0\0\0\0\0\0'),
        ByteField('startingBoundaryHops', 0),
        ByteField('boundaryHops', 0),
        BitField('reserved1', 0, 4),
        BitEnumField('actionField', 0, 4,
                     { 0: 'GET', #
                       1: 'SET', #
                       2: 'RESPONSE',
                       3: 'COMMAND',
                       4: 'ACKNOWLEDGE',
                       5: 'Reserved',
                       6: 'Reserved',
                       7: 'Reserved',
                       8: 'Reserved', 
                       9: 'Reserved', 
                       10: 'Reserved',
                       11: 'Reserved',
                       12: 'Reserved',
                       13: 'Reserved',
                       14: 'Reserved',
                       15: 'Reserved'}),
        ByteField('reserved2', 0xEA)
        ]

class PtpTlvManagement(Packet):
    name = 'PtpTlvManagement'
    fields_desc = [
        ShortEnumField('managementId',0, {0x0000:"NULL_MANAGEMENT",
                                          0x0001:"CLOCK_DESCRIPTION",
                                          0x0002:"USER_DESCRIPTION",
                                          0x0003:"SAVE_IN_NON_VOLATILE_STORAGE",
                                          0x0004:"RESET_NON_VOLATILE_STORAGE",
                                          0x0005:"INITIALIZE",
                                          0x0006:"FAULT_LOG",
                                          0x0007:"FAULT_LOG_RESET",
                                          0x2000:"DEFAULT_DATA_SET",
                                          0x2001:"CURRENT_DATA_SET",
                                          0x2002:"PARENT_DATA_SET",
                                          0x2003:"TIME_PROPERTIES_DATA_SET",
                                          0x2004:"PORT_DATA_SET",
                                          0x2005:"PRIORITY1",
                                          0x2006:"PRIORITY2",
                                          0x2007:"DOMAIN",
                                          0x2008:"SLAVE_ONLY",
                                          0x2009:"LOG_ ANNOUNCE_INTERVAL",
                                          0x200A:"ANNOUNCE_RECEIPT_TIMEOUT",
                                          0x200B:"LOG_ SYNC_INTERVAL",
                                          0x200C:"VERSION_NUMBER",
                                          0x200D:"ENABLE_PORT",
                                          0x200E:"DISABLE_PORT", 
                                          0x200F:"TIME",
                                          0x2010:"CLOCK_ACCURACY",
                                          0x2011:"UTC_PROPERTIES",
                                          0x2012:"TRACEABILITY_PROPERTIES",
                                          0x2013:"TIMESCALE_PROPERTIES",
                                          0x2014:"UNICAST_NEGOTIATION_ENABLE",
                                          0x2015:"PATH_TRACE_LIST",
                                          0x2016:"PATH_TRACE_ENABLE",
                                          0x2017:"GRANDMASTER_CLUSTER_TABLE",
                                          0x2018:"UNICAST_MASTER_TABLE",
                                          0x2019:"UNICAST_MASTER_MAX_TABLE_SIZE",
                                          0x201A:"ACCEPTABLE_MASTER_TABLE",
                                          0x201B:"ACCEPTABLE_MASTER_TABLE_ENABLED",
                                          0x201C:"ACCEPTABLE_MASTER_MAX_TABLE_SIZE", 
                                          0x201D:"ALTERNATE_MASTER",
                                          0x201E:"ALTERNATE_TIME_OFFSET_ENABLE",
                                          0x201F:"ALTERNATE_TIME_OFFSET_NAME",
                                          0x2020:"ALTERNATE_TIME_OFFSET_MAX_KEY",
                                          0x2021:"ALTERNATE_TIME_OFFSET_PROPERTIES",
                                          0x4000:"TRANSPARENT_CLOCK_DEFAULT_DATA_SET",
                                          0x4001:"TRANSPARENT_CLOCK_PORT_DATA_SET",
                                          0x4002:"PRIMARY_DOMAIN",
                                          0x6000:"DELAY_MECHANISM", 
                                          0x6001:"LOG_MIN_PDELAY_REQ_INTERVAL"})
    ]
    
class PtpPathTraceEnableTlv(Packet):
    name = 'PtpPathTraceEnableTlv'
    fields_desc = [
        FlagsField('flagField',0x00,8,[ "EN" ]),
        #ByteField('EN',0),
        ByteField('reserved',0x0008)
    ]


class PtpTlvPathTrace(Packet):
    name = 'PtpTlvPathTrace'
    pt_list = []
    fields_desc = [
        ShortField('tlvType',0x0008),
        FieldLenField("lengthField", None, count_of = "pathSequence",adjust=lambda pkt,x:(8*x)),        
        FieldListField("pathSequence", default = [], field = ClockIdentityField('', '\0\0\0\0\0\0\0\0'), count_from = lambda pkt: pkt.lengthField) 
    ]

    def post_build(self, p, pay):
        if (pay != None):
            l = len(pay)
        else:
            l = 0
        p = p[:2] + struct.pack("!H", l) + p[4:]
        return p+pay




#bind_layers( UDP,           PtpHdr,           dport=319,sport=319) 
#bind_layers( UDP,           PtpHdr,           dport=320,sport=320)
 
bind_layers( UDP,           PtpEventMsg,      dport=319,sport=319) 
bind_layers( UDP,           PtpGeneralMsg,    dport=320,sport=320) 

bind_layers( PtpGeneralMsg, PtpAnnounce,      messageType=0xB, controlField = 0x05 )
bind_layers( UDP,           PtpAnnounce,      dport=320,sport=320) 

bind_layers( PtpGeneralMsg, PtpFollowUp,      messageType=0x8, controlField = 0x02)
bind_layers( UDP,           PtpFollowUp,      dport=320,sport=320) 

bind_layers( PtpGeneralMsg, PtpDelayResp,     messageType=0x9, controlField = 0x03)
bind_layers( UDP,           PtpDelayResp,     dport=320,sport=320) 

bind_layers( PtpGeneralMsg, PtpPDelayReq,     messageType=0x2, controlField = 0x05)
bind_layers( UDP,           PtpPDelayReq,     dport=320,sport=320) 

bind_layers( PtpGeneralMsg, PtpManagement,    messageType=0xD, controlField = 0x04)
bind_layers( UDP,           PtpManagement,    dport=320,sport=320) 

bind_layers( PtpEventMsg,   PtpSync,          messageType=0x0, controlField = 0x00) 
bind_layers( UDP,           PtpSync,          dport=319,sport=319) 

bind_layers( PtpEventMsg,   PtpDelayReq,      messageType=0x1, controlField = 0x01) 
bind_layers( UDP,           PtpDelayReq,      dport=319,sport=319) 

bind_layers( PtpTlv,        PtpTlvManagement,  tlvType=0x0001)

bind_layers( PtpTlvManagement, PtpPathTraceEnableTlv, managementId=0x2016)

bind_layers( UDP,           PtpFollowUp,      dport=320,sport=320) 
#bind_layers( PtpHdr,        PtpFollowUp,      messageType='Follow_Up') 


bind_layers( UDP,           PtpDelayResp,     dport=320,sport=320) 
#bind_layers( PtpHdr,        PtpDelayResp,     messageType='Delay_Resp')

bind_layers( UDP,           PtpPDelayReq,     dport=320,sport=320) 
#bind_layers( PtpHdr,        PtpPDelayReq,     messageType='PDelay_Req') 

bind_layers( UDP,           PtpManagement,    dport=320,sport=320) 
#bind_layers( PtpHdr,        PtpManagement,    messageType='Management') 

