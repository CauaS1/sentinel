# Sentinel

Sentinel is a Python-based Network Detection and Response (NDR) application designed to monitor network activity, detect suspicious behavior, and automatically respond to basic network threats.

This project was created as a hands-on way to understand how modern network monitoring and detection systems work internally by implementing their core concepts from scratch.

### 🤖 Packet Metadata Collection
- Packet number
- Timestamps
- MAC (source and destination)
- IP (source and destination)
- Protocol

### 🚨 Detection Features
- Normal Event
  - Packet metadata is stored in the events database.
- Alert
  - Suspicious activity is recorded in the alerts database.
- Blacklist
  - The source IP is added to the blacklist database.
  - An inbound firewall rule is automatically created to block future connections.
- Log file
  - Every captured packet is recorded in a raw `.log` file.

### ⚠️ Bugs detected to fix
- [ ] Incorrect request counting across time windows.
    - Currently, requests are accumulated indefinitely. For example, a request made at 2:00 PM and another at 4:00 PM are still counted together, eventually causing legitimate hosts to exceed the configured threshold


### 🚀 Future upgrades
  __v 1.0.1__
- [ ] Docker image for easy deployment
- [x] Whitelist
- [x] JSON configuration file for flexibility
- [ ] Source / Destination Ports for new analysis and detection rules


__v 1.0.2__
...



  
 

 


