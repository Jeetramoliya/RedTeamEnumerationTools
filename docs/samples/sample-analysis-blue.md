# EnumGod blue-team report

What an attacker could do here, and what to detect/remediate. Generated from the same findings.

## T1003.001
- **[MEDIUM/LIKELY] WS01** - WDigest UseLogonCredential=1 - CLEARTEXT passwords cached in LSASS
  - Remediate: Enable LSA PPL + Credential Guard; set WDigest UseLogonCredential=0.
  - Detect: alert on activity matching T1003.001 on WS01 (see docs/DETECTION.md).

## T1003.002
- **[HIGH/LIKELY] WS01** - Token holds SeBackupPrivilege (Enabled): Read any file -> dump SAM/SYSTEM/NTDS.dit
  - Remediate: Apply the fixing update; fix config\SAM ACLs; delete exposing VSS copies.
  - Detect: alert on activity matching T1003.002 on WS01 (see docs/DETECTION.md).
- **[HIGH/POTENTIAL] WS01** - Backup/Restore privilege on a domain-reachable host -> NTDS/hive dump
  - Remediate: Apply the fixing update; fix config\SAM ACLs; delete exposing VSS copies.
  - Detect: alert on activity matching T1003.002 on WS01 (see docs/DETECTION.md).

## T1003.006
- **[HIGH/POTENTIAL] SYNC01** - AAD Connect sync server -> on-prem <-> cloud identity pivot
  - Remediate: Restrict DS-Replication-Get-Changes* to DCs; audit non-default principals.
  - Detect: alert on activity matching T1003.006 on SYNC01 (see docs/DETECTION.md).

## T1543.003
- **[HIGH/LIKELY] WS01** - Writable service binary: FooSvc
  - Remediate: Remove non-admin write on service dirs / PATH.
  - Detect: alert on activity matching T1543.003 on WS01 (see docs/DETECTION.md).

## T1558.003
- **[HIGH/LIKELY] DC01** - Kerberoastable user: svc_sql (SPN set)
  - Remediate: Use (g)MSAs / 25+ char service-account passwords; AES-only; monitor 4769.
  - Detect: alert on activity matching T1558.003 on DC01 (see docs/DETECTION.md).

## T1558/T1134
- **[HIGH/LIKELY] DC01** - Unconstrained delegation (computer): WS01 - coerce + capture DC TGT (printerbug/petitpotam)
  - Remediate: Remove unneeded delegation; mark sensitive accounts 'not delegated'.
  - Detect: alert on activity matching T1558/T1134 on DC01 (see docs/DETECTION.md).
- **[HIGH/POTENTIAL] DC01** - Unusual delegation + credential-exposure combination
  - Remediate: Remove unneeded delegation; mark sensitive accounts 'not delegated'.
  - Detect: alert on activity matching T1558/T1134 on DC01 (see docs/DETECTION.md).
- **[HIGH/POTENTIAL] DC01** - Unconstrained delegation + coercion path to Domain Admin
  - Remediate: Remove unneeded delegation; mark sensitive accounts 'not delegated'.
  - Detect: alert on activity matching T1558/T1134 on DC01 (see docs/DETECTION.md).

## T1649
- **[HIGH/LIKELY] DC01** - AD CS enterprise CA present: ca.corp
  - Remediate: Fix template flags; require manager approval; restrict enroll.
  - Detect: alert on activity matching T1649 on DC01 (see docs/DETECTION.md).
- **[HIGH/POTENTIAL] DC01** - AD CS present + relayable auth -> ESC8 web-enrollment relay
  - Remediate: Fix template flags; require manager approval; restrict enroll.
  - Detect: alert on activity matching T1649 on DC01 (see docs/DETECTION.md).

## unmapped
- **[HIGH/LIKELY] SYNC01** - Azure AD Connect (ADSync) service present on THIS host - tier-0
  - Remediate: Review and apply least privilege.
  - Detect: alert on activity matching unmapped on SYNC01 (see docs/DETECTION.md).
- **[MEDIUM/LIKELY] DC01** - ms-DS-MachineAccountQuota=10 - any user can add machine accounts
  - Remediate: Review and apply least privilege.
  - Detect: alert on activity matching unmapped on DC01 (see docs/DETECTION.md).
