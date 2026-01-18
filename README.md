# 2am in Pampas
##  Topolgy Analysis of Illogical Traffic Pattern - SFR France + Argentine ISP

> **TL;DR**: iOS device in Atlanta routing to French telecom + small Argentine ISP using BoringSSL (Google's crypto library) at 2-3 AM. No legitimate reason for this path.

[![Threat Level](https://img.shields.io/badge/Threat%20Level-HIGH-red)]()
[![Detection](https://img.shields.io/badge/Detection-BoringSSL%20on%20iOS-orange)]()
[![Location](https://img.shields.io/badge/Location-Atlanta%2C%20GA-blue)]()
[![Date](https://img.shields.io/badge/Date-Jan%209--18%2C%202026-lightgrey)]()

---

## 📊 Network Flow Visualization

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EXPECTED BEHAVIOR                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   iPhone (Atlanta) ──────────► Apple Servers (17.x.x.x)             │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────┐
│                         ACTUAL BEHAVIOR                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   iPhone (Atlanta)                                                   │
│         │                                                             │
│         ├──────────────────────► 109.1.2.1 (SFR France)             │
│         │                         [Paris, Europe]                    │
│         │                         TLS 1.3 + BoringSSL                │
│         │                         02:00-03:30 AM                     │
│         │                                                             │
│         ├──────────────────────► 200.3.10.2 (Argentina)             │
│         │                         [INTERWEB-DAIREAUX]                │
│         │                         Small ISP (~6k subs)               │
│         │                                                             │
│         ├──────────────────────► 67.1.2.1 (CenturyLink)             │
│         ├──────────────────────► 184.0.0.13 (CenturyLink)           │
│         └──────────────────────► 136.3.5.1 (Amazon AWS)             │
│                                                                       │
│   ❌ 3 Continents  ❌ No VPN  ❌ BoringSSL on iOS                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Findings

| Category | Details |
|----------|---------|
| **Device** | iPhone SOS Mode (no SIM/eSIM) |
| **Location** | Atlanta, GA |
| **Time Period** | January 9-18, 2026 |
| **Primary Concern** | **BoringSSL on iOS** (Google's TLS library - not native iOS) |
| **Traffic Time** | 02:00-03:30 AM (off-hours) |
| **Threat Assessment** | Likely malware/C2 infrastructure |

---

## Suspicious IP Addresses

### Primary Targets

```yaml
109.1.2.1:
  Owner: SFR/Altice France
  Block: 109.1.0.0/17 (INFRA-SBT)
  Location: Paris, France
  Protocol: TLS 1.3, QUIC, BoringSSL
  Why Suspicious: No legitimate reason for Atlanta → Paris routing

200.3.10.2:
  Owner: INTERWEB-DAIREAUX S.R.L.
  Block: 200.3.10.0/23
  Location: Daireaux, Argentina
  Size: ~6,000 subscribers (small town ISP)
  Why Suspicious: No US operations, no CDN presence
```

### Secondary Targets

| IP | Owner | Location |
|----|-------|----------|
| 67.1.2.1 | CenturyLink/Lumen | USA |
| 184.0.0.13 | CenturyLink/Lumen | USA |
| 136.3.5.1 | Amazon AWS | USA |

---

## TLS Fingerprint

<details>
<summary><b>Click to expand technical details</b></summary>

```yaml
Protocol: TLS 1.3
Cipher Suite: TLS_AES_256_GCM_SHA384
ALPN: h2 (HTTP/2)
Implementation: BoringSSL (Google's library)

🚩 RED FLAG: iOS devices should use SecureTransport or Network.framework
              NOT BoringSSL (suggests custom implementation or malware)

Handshake Sequence:
  - ClientHello (BoringSSL)
  - ServerHello 
  - encrypted_extensions
  - certificate verification
  - TLS 1.3 session established
```

**Why This Matters**: Legitimate iOS apps use Apple's native TLS stack. BoringSSL indicates a third-party app bundling its own crypto library, which is common in malware to avoid detection.

</details>

---

## 📈 Detection Signatures

### For Network Operators

Monitor your networks for this pattern:

```yaml
Source: iOS devices (any)
Destinations: 
  - 109.1.0.0/17 (SFR France)
  - 200.3.10.0/23 (Argentine ISP)
Time: 02:00-04:00 local
Protocol: TLS 1.3
Cipher: TLS_AES_256_GCM_SHA384
Implementation: BoringSSL
ALPN: h2

Alert if: iOS device + BoringSSL + foreign non-CDN endpoint
```

### IDS/Firewall Rules

```bash
# Suricata/Snort
alert tls any any -> [109.1.2.1, 200.3.10.2] 443 (
  msg: "Suspicious BoringSSL to SFR/Argentina";
  tls.version: 1.3;
  tls.ciphersuites: TLS_AES_256_GCM_SHA384;
  threshold: type threshold, track by_src, count 1, seconds 3600;
  sid: 1000001;
)

# Firewall block
deny ip any 109.1.0.0/17 log "SFR France block"
deny ip any 200.3.10.0/23 log "Argentine ISP block"
```

---

## 📁 Evidence Files

All diagnostic files captured from iPhone after network reset:

| File | Size | Contains |
|------|------|----------|
| `00000000000000b9.tracev3` | 10 MB | **109.1.2.1 connection** ⭐ |
| `00000000000000b8.tracev3` | 10 MB | 67.1.2.1 connection |
| `0000000000000071.tracev3` | 2.1 MB | 136.3.5.1, 184.0.0.13 |
| `0000000000000072.tracev3` | 1.9 MB | 200.3.10.2 connection |
| `logdata_LiveData.tracev3` | 3 MB | Network reset logs |

<details>
<summary><b>What's in the files?</b></summary>

- Connection timestamps
- TLS handshake details
- Port numbers (443 = HTTPS)
- Protocol information (TLS 1.3, QUIC)
- Process IDs and attributions
- Network interface data (WiFi)
- BoringSSL library references
- Certificate validation logs

</details>

---

## 🔍 Analysis Summary

### What Is Known

- Device in SOS mode (no cellular service, WiFi only)
- Cellular data confirmed: **0 bytes** (WiFi connections only)
- All operators are legitimate (SFR, CenturyLink, AWS, Argentine ISP)
- TLS encryption properly validated (not MITM)
- BoringSSL implementation (unusual for iOS)
- Off-hours activity pattern (2-3 AM)

### What Doesn't Make Sense 

- Atlanta device routing to French telecom (no VPN configured)
- Small Argentine ISP in the path (no business connection)
- BoringSSL on iOS (should use Apple's TLS stack)
- Geographic spread across 3 continents (inefficient routing)
- CenturyLink appearing twice (different IP blocks)
- 2-3 AM timing (suspicious for background activity)

### Likely Explanation 

**Malware/Botnet C2 Infrastructure**

The combination of:
- BoringSSL on iOS (custom crypto implementation)
- Foreign endpoints (France, Argentina)
- Off-hours timing (2-3 AM)
- No legitimate operational reason
- Process marked as "developer" (not Apple system service)

...strongly suggests compromised device using C2 infrastructure.

---

## 🛡️ Mitigation Steps

1. **Monitor for this pattern** in your NetFlow/sFlow data
2. **Block or alert** on 109.1.0.0/17 and 200.3.10.0/23 from non-EU/LACNIC sources
3. **Flag BoringSSL traffic** from iOS devices
4. **Share findings** with security community
5. **Contact abuse teams** at SFR and Argentine ISP

---


##  Why This Matters to Network Operators

If this is malware (which the pattern strongly suggests), it's not affecting just one device:

✅ **Check your own networks** for this traffic pattern  
✅ **Other devices may be infected** and you don't know it yet  
✅ **Detection signatures provided** above for immediate deployment  
✅ **Early detection** prevents data exfiltration and spread  
✅ **Community coordination** helps identify scope of infection  

---

## 📊 Timeline

```
Jan 9-16, 2026:  Background connections to suspicious IPs
Jan 18, 02:00:   Connection to 109.1.2.1 (SFR France)
Jan 18, 02:00-03:30: Active TLS sessions, BoringSSL detected
Jan 18, 14:16:   User performs network reset (troubleshooting)
Jan 18, 14:17:   Diagnostics captured, evidence collected
Jan 18, 20:00+:  Analysis performed, patterns identified
```


---



## Legal / Ethical Notes

- All data extracted from legitimate iOS diagnostics (user-initiated)
- No hacking, cracking, or unauthorized access performed
- Sharing for defensive purposes and community protection
- Network operators encouraged to monitor and protect their networks

---

## 📧 Contact

For questions or additional data:

- **GitHub**: Open an issue on this repo

---



<div align="center">

**Help protect the community - check your networks for this pattern**

[![Check Your Network](https://img.shields.io/badge/Action-Check%20Your%20Network-brightgreen)]()
[![Report Findings](https://img.shields.io/badge/Action-Report%20Findings-blue)]()
[![Share Intel](https://img.shields.io/badge/Action-Share%20Intel-orange)]()

</div>
