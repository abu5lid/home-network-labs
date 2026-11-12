# Wi-Fi Attack Lab: WPA3 Deauthentication and MITM

## Overview

I tested deauthentication attacks and LAN-side man-in-the-middle techniques against my own home Wi-Fi network, which uses WPA3-SAE. The key outcome: over-the-air deauthentication was **not effective** against WPA3-SAE with Protected Management Frames (PMF) required, while the LAN-side ARP-spoofing MITM succeeded. The lab also produced a personal correction: my first interpretation of the deauth results was wrong, and packet analysis corrected it.

Scope and authorization: all networks and devices tested are my own property. Testing was performed from a Kali Linux laptop with an Alfa AWUS036ACM adapter in monitor mode.

## Reconnaissance

I mapped the RF environment with airodump-ng across both bands:

```bash
sudo airodump-ng wlan0mon --band abg
```

Findings:

- All of my access points advertise WPA3-SAE with CCMP; no WPA2-only networks.
- My SSIDs are hidden, so I identified my APs by signal strength and by association/probe activity rather than by name.
- One of my APs also emits an open network on 5 GHz — flagged as a security finding below.

## Deauthentication Testing

I ran broadcast and directed deauthentication attacks using aireplay-ng:

```bash
# Broadcast
sudo aireplay-ng --deauth 10 -a <BSSID> wlan0mon

# Directed at one client
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
```

aireplay-ng reported ACKs, which at first suggested the deauths were landing. However, ACKs only confirm radio-layer delivery; they do not confirm the client or AP accepted the frame. That distinction became the central lesson of this lab.

## Capture Analysis and the PMF Correction

I analyzed the captures (with Scapy) after the attacks. The evidence:

- The beacon's RSN Information Element shows AKM suite SAE, cipher CCMP-128, **Management Frame Protection Capable = 1, Management Frame Protection Required = 1**. PMF is required, not optional.
- The capture contains roughly 1,280 broadcast deauthentication frames, but the client (my own laptop) **never disassociated as a result**. Instead, the client attempted SAE authentication exchanges repeatedly, and the AP rejected each attempt with status code 126.
- Status code 126 is `WLAN_STATUS_SAE_HASH_TO_ELEMENT`, defined in hostapd's `ieee802_11_defs.h`. This status indicates the AP requires the SAE Hash-to-Element (H2E) password derivation method and the client was not negotiating it correctly — an association compatibility failure, not a deauthentication effect.
- The capture contains no EAPOL key frames and no successful association, confirming the deauths never translated into a completed disconnect-and-reconnect cycle I could capture and decrypt.

**Conclusion:** the deauthentication attack did not work against my network. WPA3-SAE mandates PMF, and my AP has it required, which protects deauthentication and disassociation frames from forgery. My initial read — that the deauth had succeeded — was wrong; the visible disconnect I saw was my own laptop failing SAE association, not a successful attack. Verifying from the capture, rather than trusting the terminal output and the apparent disconnect, corrected the finding.

For comparison, the same testing against a WPA2 network would not have this protection, since PMF is optional in WPA2 and only mandatory in WPA3.

## Why WPA3 Captures Cannot Be Decrypted With the Password

A separate objective was decrypting captured WPA3 traffic in Wireshark using the network password. This is not possible: in WPA3-SAE, each connection derives its own PMK for forward secrecy, so capturing the 4-way handshake and knowing the password is not enough. The PMK must be extracted from the client or AP itself (for example, by running wpa_supplicant or hostapd with the `-d -K` flags) and used as the decryption key. See the [Wireshark 802.11 decryption wiki](https://gitlab.com/wireshark/wireshark/-/wikis/HowToDecrypt802.11) for details.

## LAN-Side MITM with bettercap

Since Wi-Fi encryption defeats passive capture, I moved to the LAN side. With my laptop joined to the target SSID:

```text
sudo bettercap -iface wlan0
net.probe on
set arp.spoof.targets <TARGET_IP>
set arp.spoof.internal false
arp.spoof on
net.sniff on
```

Results:

- Discovery identified the target (a Chromebook) and the gateway.
- After enabling the spoofer, the target's traffic began transiting my laptop, and net.sniff reported mDNS traffic.
- bettercap restored the target's ARP cache cleanly on exit, which is the correct way to end a session.

This succeeded regardless of Wi-Fi security because ARP spoofing operates at Layer 2, after the access point has already decrypted the wireless frames. The traffic itself was HTTPS/QUIC encrypted, so the capture yielded metadata (domains, connection patterns) rather than content.

## Findings and Remediation

- **Deauthentication resisted by WPA3-SAE with PMF required:** This is expected behavior, not a gap. No remediation needed; keep WPA3-SAE with PMF required on all SSIDs.
- **Open network emitted by my own AP:** One of my APs broadcasts an unencrypted SSID on 5 GHz. I will disable or secure that SSID. An open network on my own hardware is unnecessary exposure.
- **ARP spoofing succeeds on the LAN:** The network has no ARP-spoofing defenses. On managed switches, Dynamic ARP Inspection and DHCP snooping mitigate this; on a home router, the practical defense is that sensitive traffic is TLS-encrypted. Detection could come from monitoring for duplicate ARP replies.

## Lessons Learned

- Terminal output can mislead. aireplay-ng's ACK counts only prove the frames were transmitted and heard — not that the target accepted them. Confirm attacks from packet captures.
- Status codes matter. The rejections were status 126 (SAE Hash-to-Element), which explained the failed associations and corrected my interpretation of the deauth results.
- WPA3-SAE with PMF required closes the classic over-the-air attack path (deauth + handshake capture + password cracking). The network side becomes the softer target.

## Sources

- [Wireshark: How to Decrypt 802.11](https://gitlab.com/wireshark/wireshark/-/wikis/HowToDecrypt802.11)
- [hostapd ieee802_11_defs.h (status code definitions)](https://w1.fi/cgit/hostap/plain/src/common/ieee802_11_defs.h)
- [Wi-Fi Alliance: Protected Management Frames](https://www.wi-fi.org/beacon/philipp-ebbecke/protected-management-frames-enhance-wi-fi-network-security)
- [bettercap: arp.spoof module](https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/)
