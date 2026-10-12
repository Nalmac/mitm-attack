# Man-in-the-middle attack

This project aims to study the workings of a man in the middle attack. This code will try to impersonate the router on your current network, in order to spy on every other machine connected on that same network.

> [!WARNING]
> Please note that doing this on a network you do not own might not be a good idea...Thus, I have included an automatic lab setup, in `up.sh`. Launching this on Linux should allow you to safely experiment with the code and the concepts of the attack.

## Attack details

The attack starts by trying to completely exhaust the address pool of the current DHCP server (that's `dhcp_starvation.c`). For each address that it successfully blocks out, the program stores it in its own address pool, in order to distribute it later.
Once the DHCP server stops answering, the program launches a rogue DHCP server, which hands out the addresses previously stolen (`dhcp_server.c`). The connection parameters handed out alongside the addresses set the attacker's machine as DNS server and gateway.
Obviously, this is where `dns_parser.c` and `dns_proxy.c` come into play : the program allows for a watchlist to be set up. Once a flagged domain is detected by the proxy, it is redirected to an address the attacker controls. Otherwise, it behaves as a straightforward DNS proxy.

## Trying it out

If you wish to try the attack out, please compile the program with `make`. I strongly advise using the lab environment to try and mitigate any leak into a used network, as it can disrupt the service for legitimate users.
If you choose do use the lab environment, you will have to start a DHCP server on the `lab-srv` namespace. I used dnsmasq to do this in my tests.

In order to execute any command from a network namespace, use this syntax :

```bash
sudo ip netns execute [namespace] [command] 
```
