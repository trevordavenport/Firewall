Firewall
========

### High-Level Explanation ###
```
  Custom Firewall written in Python that checks connections based on type (UDP, DNS, TCP, ICMP).
  Parses packets for specific criteria (source IP, dest IP, etc.)
```
![](http://i.imgur.com/lY8KHLO.png)

### Rules of Firewall ###
```
  * Based on given Allow/Deny Rules, we either accept connections or drop.
  * Follows a Rules.conf file
  * Parses GeoIP Database File for Accepted Known Connections
```
