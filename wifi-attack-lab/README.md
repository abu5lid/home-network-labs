# Wi-Fi Attack Lab: WPA3 Deauthentication and MITM

## Overview
I tested deauthentication attacks and a LAN-side man-in-the-middle attack against my own home Wi-Fi network, which uses WPA3-SAE. The deauthentication attacks did not work: my access point requires Protected Management Frames (PMF), which protects deauthentication frames from forgery. The ARP-spoofing MITM with bettercap did work. At first I believed the deauth had succeeded, but analyzing the packet captures showed it had not.

Scope and authorization: all networks and devices tested are my own property. Testing was performed from a Kali Linux laptop with an Alfa AWUS036ACM adapter in monitor mode. Network identifiers (SSIDs, BSSIDs, MAC addresses, and IP addresses) are redacted.

## Reconnaissance
I mapped the RF environment with airodump-ng across both bands:

```bash
sudo airodump-ng wlan0mon --band abg
```

The scan showed that all of my access points use WPA3-SAE with CCMP, and that my SSIDs are hidden. Since the SSIDs were hidden, I identified my APs by signal strength and by association and probe activity instead of by name. I also found that one of my APs broadcasts an open network on 5 GHz, which I noted as a finding below.

## Deauthentication Testing
I ran broadcast and directed deauthentication attacks with aireplay-ng:

```bash
sudo aireplay-ng --deauth 10 -a <BSSID> wlan0mon
sudo aireplay-ng --deauth 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
```

aireplay-ng reported ACKs, so at first I believed the deauths were landing. ACKs only confirm that the frames were heard at the radio layer, though. They do not confirm that the client or the AP accepted the frame.

## Capture Analysis
I analyzed the captures with Scapy after the attacks.

- The beacon's RSN Information Element shows AKM suite SAE, cipher CCMP-128, Management Frame Protection Capable = 1, and Management Frame Protection Required = 1. PMF is required, not optional.
- The capture contains about 1,280 broadcast deauthentication frames. The client (my own laptop) never disassociated because of them. Instead, it attempted SAE authentication repeatedly, and the AP rejected each attempt with status code 126.
- Status code 126 is `WLAN_STATUS_SAE_HASH_TO_ELEMENT`, defined in hostapd's `ieee802_11_defs.h`. The AP requires the SAE Hash-to-Element (H2E) password derivation method, and the client was not negotiating it correctly. That is an association compatibility failure, not a deauthentication effect.
- The capture contains no EAPOL key frames and no successful association, so there was no disconnect-and-reconnect cycle that I could capture and decrypt.

The deauthentication attack did not work against my network. WPA3-SAE requires PMF, and my AP has it set to required, which protects deauthentication and disassociation frames from forgery. The disconnect I saw while running the attack was my own laptop failing SAE association, not the deauth working. Checking the capture instead of trusting the terminal output corrected my conclusion.

The same test against a WPA2 network would not have this protection, since PMF is optional in WPA2 and only mandatory in WPA3.

## WPA3 Capture Decryption
I also wanted to decrypt the captured WPA3 traffic in Wireshark using the network password. This is not possible. In WPA3-SAE, each connection derives its own PMK for forward secrecy, so capturing the 4-way handshake and knowing the password is not enough. The PMK has to be extracted from the client or the AP itself, for example by running wpa_supplicant or hostapd with the `-d -K` flags, and then used as the decryption key. The [Wireshark 802.11 decryption wiki](https://gitlab.com/wireshark/wireshark/-/wikis/HowToDecrypt802.11) describes this in detail.

## LAN-Side MITM with bettercap
Since the Wi-Fi side defeated passive capture, I moved to the LAN side. I connected my laptop to the target SSID and ran bettercap:

```text
sudo bettercap -iface wlan0
net.probe on
set arp.spoof.targets <TARGET_IP>
set arp.spoof.internal false
arp.spoof on
net.sniff on
```

Discovery found the target, a Chromebook, and the gateway. After I enabled the spoofer, the target's traffic began passing through my laptop, and net.sniff reported mDNS traffic. When I ended the session, bettercap restored the target's ARP cache.

This worked regardless of Wi-Fi security because ARP spoofing happens at Layer 2, after the access point has already decrypted the wireless frames. The captured traffic was HTTPS/QUIC encrypted, so I saw metadata such as domains and connection patterns, not content.

## Findings and Remediation

- **Deauthentication resisted by WPA3-SAE with PMF required:** Expected behavior, not a gap. I will keep WPA3-SAE with PMF required on all SSIDs.
- **Open network on my own AP:** One of my APs broadcasts an unencrypted SSID on 5 GHz. I will disable or secure that SSID.
- **ARP spoofing works on the LAN:** My network has no ARP-spoofing defenses. Dynamic ARP Inspection and DHCP snooping mitigate this on managed switches. On a home router, the practical defense is that sensitive traffic is TLS-encrypted. Detection could come from monitoring for duplicate ARP replies.

## Lessons Learned

- aireplay-ng's ACK counts only prove the frames were transmitted and heard, not that the target accepted them. I confirmed the attack result from the packet captures.
- Status codes matter. The rejections were status 126 (SAE Hash-to-Element), which explained the failed associations and corrected my interpretation of the results.
- WPA3-SAE with PMF required closes the classic over-the-air attack path (deauth, handshake capture, password cracking). The LAN behind the AP is the softer target.

## Sources

- [Wireshark: How to Decrypt 802.11](https://gitlab.com/wireshark/wireshark/-/wikis/HowToDecrypt802.11)
- [hostapd ieee802_11_defs.h (status code definitions)](https://w1.fi/cgit/hostap/plain/src/common/ieee802_11_defs.h)
- [Wi-Fi Alliance: Protected Management Frames](https://www.wi-fi.org/beacon/philipp-ebbecke/protected-management-frames-enhance-wi-fi-network-security)
- [bettercap: arp.spoof module](https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/)
