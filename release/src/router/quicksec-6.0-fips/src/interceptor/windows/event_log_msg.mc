;////////////////////////////////////////////////////////////////////////////
;// event_log_msg.mc
;//
;// @copyright
;// Copyright (c) 2000 - 2014, INSIDE Secure Oy.  All rights reserved.
;//
;// This file contains the message definitions for Windows event logging
;////////////////////////////////////////////////////////////////////////////
;

MessageIdTypedef=NTSTATUS

FacilityNames=(System=0x0
               RpcRunTime=0x2:FACILITY_RPC_RUNTIME
               RpcStubs=0x3:FACILITY_RPC_STUBS
               Io=0x4:FACILITY_IO_ERROR_CODE
               QuickSec=0x7:FACILITY_SSHIPSEC_ERROR_CODE
               )

MessageId=1000
SymbolicName=SSH_MSG_INFORMATIONAL
Severity=Informational
Facility=QuickSec
Language=English
INSIDE Secure QuickSec (Info): %2
.

MessageId=1001
SymbolicName=SSH_MSG_NOTICE
Severity=Informational
Facility=QuickSec
Language=English
INSIDE Secure QuickSec (Notice): %2
.

MessageId=1002
SymbolicName=SSH_MSG_WARNING
Severity=Warning
Facility=QuickSec
Language=English
INSIDE Secure QuickSec (Warning): %2
.

MessageId=1003
SymbolicName=SSH_MSG_ERROR
Severity=Error
Facility=QuickSec
Language=English
INSIDE Secure QuickSec (Error): %2
.

MessageId=1004
SymbolicName=SSH_MSG_CRITICAL
Severity=Error
Facility=QuickSec
Language=English
INSIDE Secure QuickSec (Fatal Error): %2
.
