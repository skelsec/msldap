import enum

# https://msdn.microsoft.com/en-us/library/cc236650.aspx
class NegotiateFlags(enum.IntFlag):
	NEGOTIATE_56   = 0x80000000
	NEGOTIATE_KEY_EXCH   = 0x40000000
	NEGOTIATE_128   = 0x20000000
	r1  = 0x10000000
	r2  = 0x8000000
	r3  = 0x4000000
	NEGOTIATE_VERSION   = 0x2000000
	r4  = 0x1000000
	NEGOTIATE_TARGET_INFO   = 0x800000
	REQUEST_NON_NT_SESSION_KEY   = 0x400000
	r5  = 0x200000
	NEGOTIATE_IDENTIFY   = 0x100000
	NEGOTIATE_EXTENDED_SESSIONSECURITY   = 0x80000
	r6  = 0x40000
	TARGET_TYPE_SERVER   = 0x20000
	TARGET_TYPE_DOMAIN   = 0x10000
	NEGOTIATE_ALWAYS_SIGN   = 0x8000
	r7  = 0x4000
	NEGOTIATE_OEM_WORKSTATION_SUPPLIED   = 0x2000
	NEGOTIATE_OEM_DOMAIN_SUPPLIED   = 0x1000
	J   = 0x800
	r8  = 0x400
	NEGOTIATE_NTLM   = 0x200
	r9  = 0x100
	NEGOTIATE_LM_KEY   = 0x80
	NEGOTIATE_DATAGRAM   = 0x40
	NEGOTIATE_SEAL   = 0x20
	NEGOTIATE_SIGN   = 0x10
	r10 = 0x8
	REQUEST_TARGET   = 0x4
	NTLM_NEGOTIATE_OEM   = 0x2
	NEGOTIATE_UNICODE   = 0x1
		
NegotiateFlagExp = {
	NegotiateFlags.NEGOTIATE_56   : 'requests 56-bit encryption. If the client sends NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN with NTLMSSP_NEGOTIATE_56 to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_56 to the client in the CHALLENGE_MESSAGE.   Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_56 if it is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_56.',
	NegotiateFlags.NEGOTIATE_KEY_EXCH   : 'requests an explicit key exchange. This capability SHOULD be used because it improves security for message integrity or confidentiality. See sections 3.2.5.1.2, 3.2.5.2.1, and 3.2.5.2.2 for details. An alternate name for this field is NTLMSSP_NEGOTIATE_KEY_EXCH.',
	NegotiateFlags.NEGOTIATE_128  : 'requests 128-bit session key negotiation. An alternate name for this field is NTLMSSP_NEGOTIATE_128. If the client sends NTLMSSP_NEGOTIATE_128 to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_128 to the client in the CHALLENGE_MESSAGE only if the client sets NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN. Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_128 if it is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_128.<23>',
	NegotiateFlags.r1  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.r2  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.r3  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_VERSION   : 'requests the protocol version number. The data corresponding to this flag is provided in the Version field of the NEGOTIATE_MESSAGE, the CHALLENGE_MESSAGE, and the AUTHENTICATE_MESSAGE.<24> An alternate name for this field is NTLMSSP_NEGOTIATE_VERSION.',
	NegotiateFlags.r4  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_TARGET_INFO   : 'indicates that the TargetInfo fields in the CHALLENGE_MESSAGE (section 2.2.1.2) are populated. An alternate name for this field is NTLMSSP_NEGOTIATE_TARGET_INFO.',
	NegotiateFlags.REQUEST_NON_NT_SESSION_KEY   : ' requests the usage of the LMOWF. An alternate name for this field is NTLMSSP_REQUEST_NON_NT_SESSION_KEY.',
	NegotiateFlags.r5  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_IDENTIFY   : 'requests an identify level token. An alternate name for this field is NTLMSSP_NEGOTIATE_IDENTIFY.',
	NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY  : 'requests usage of the NTLM v2 session security. NTLM v2 session security is a misnomer because it is not NTLM v2. It is NTLM v1 using the extended session security that is also in NTLM v2. NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and NTLMSSP_NEGOTIATE_LM_KEY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client. NTLM v2 authentication session key generation MUST be supported by both the client and the DC in order to be used, and extended  session security signing and sealing requires support from the client and the server in order to be used.<25> An alternate name for this field is NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.',
	NegotiateFlags.r6  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.TARGET_TYPE_SERVER   : 'TargetName MUST be a server name. The data corresponding to this flag is provided by the server in the TargetName field of the CHALLENGE_MESSAGE. If this bit is set, then NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set. This flag MUST be ignored in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field is NTLMSSP_TARGET_TYPE_SERVER.',
	NegotiateFlags.TARGET_TYPE_DOMAIN   : 'TargetName MUST be a domain name. The data corresponding to this flag is provided by the server in the TargetName field of the CHALLENGE_MESSAGE. then NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set. This flag MUST be ignored in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field is NTLMSSP_TARGET_TYPE_DOMAIN.',
	NegotiateFlags.NEGOTIATE_ALWAYS_SIGN   : ' requests the presence of a signature block on all messages. NTLMSSP_NEGOTIATE_ALWAYS_SIGN MUST be set in the NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. NTLMSSP_NEGOTIATE_ALWAYS_SIGN is overridden by NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL, if they are supported. An alternate name for this field is NTLMSSP_NEGOTIATE_ALWAYS_SIGN.',
	NegotiateFlags.r7  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_OEM_WORKSTATION_SUPPLIED   : 'This flag indicates whether the Workstation field is present. If this flag is not set, the Workstation field MUST be ignored. If this flag is set, the length of the Workstation field specifies whether the workstation name is nonempty or not.<26> An alternate name for this field is NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.',
	NegotiateFlags.NEGOTIATE_OEM_DOMAIN_SUPPLIED   : 'the domain name is provided (section 2.2.1.1).<27> An alternate name for this field is NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.',
	NegotiateFlags.J   : 'the connection SHOULD be anonymous.<28>',
	NegotiateFlags.r8  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_NTLM   : 'requests usage of the NTLM v1 session security protocol. NTLMSSP_NEGOTIATE_NTLM MUST be set in the NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for this field is NTLMSSP_NEGOTIATE_NTLM.',
	NegotiateFlags.r9  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_LM_KEY   : 'requests LAN Manager (LM) session key computation. NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client. NTLM v2 authentication session key generation MUST be supported by both the client and the DC in order to be used, and extended session security signing and sealing requires support from the client and the server to be used. An alternate name for this field is NTLMSSP_NEGOTIATE_LM_KEY.',
	NegotiateFlags.NEGOTIATE_DATAGRAM   : 'requests connectionless authentication. If NTLMSSP_NEGOTIATE_DATAGRAM is set, then NTLMSSP_NEGOTIATE_KEY_EXCH MUST always be set in the AUTHENTICATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for this field is NTLMSSP_NEGOTIATE_DATAGRAM',
	NegotiateFlags.NEGOTIATE_SEAL   : 'requests session key negotiation for message confidentiality. If the client sends NTLMSSP_NEGOTIATE_SEAL to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_SEAL to the client in the CHALLENGE_MESSAGE. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD always set NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128, if they are supported. An alternate name for this field is NTLMSSP_NEGOTIATE_SEAL.',
	NegotiateFlags.NEGOTIATE_SIGN   : 'requests session key negotiation for message signatures. If the client sends NTLMSSP_NEGOTIATE_SIGN to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE. An alternate name for this field is NTLMSSP_NEGOTIATE_SIGN.',
	NegotiateFlags.r10 : 'This bit is unused and MUST be zero.',
	NegotiateFlags.REQUEST_TARGET   : 'TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST be supplied. An alternate name for this field is NTLMSSP_REQUEST_TARGET.',
	NegotiateFlags.NTLM_NEGOTIATE_OEM   : 'requests OEM character set encoding. An alternate name for this field is NTLM_NEGOTIATE_OEM. See bit A for details.',
	NegotiateFlags.NEGOTIATE_UNICODE   : 'requests Unicode character set encoding. An alternate name for this field is NTLMSSP_NEGOTIATE_UNICODE.',

}