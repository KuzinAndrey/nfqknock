# nfqknockd - protect TCP port by cryptographic port-knocking

TODO description here.

## Compile

Alpine Linux:
```sh
# Build dependencies
apk add libnfnetlink-dev
apk add libnetfilter_queue-dev

# Build project
make

# Install in /usr/local
make install
```

## Usage

```sh
$ ./nfqknockd -h
Usage: ./nfqknockd [options]
Options:
  -f           Running foreground
  -p <port>    Guard TCP port (can be used multiple times)
  -t <seconds> Timeout for knock sequence (default: 10)
  -o <secret>  Open secret (default: helloworld123)
  -c <secret>  Close secret (default: goodbyeworld123)
  -s           Print current secret port sequences (OPEN: and CLOSE: for shell scripts)
  -d <digest>  Digest type - md5, sha256, sha384, sha512 (default: md5)
  -q <queue>   Netfilter queue number (default: 100)
  -m <maxlen>  Netfilter max queue length (default: 10000)
  -h           Print this help
Decription:
  This is nfqknockd - daemon for guard TCP ports and open/close by
  cryptographically generated port-knocking sequences rotated every hour.
  It based on NFQUEUE library and require less resources than libpcap based.
  Not need interface working in promisc mode for capture knock packets.
Author:
  Kuzin Andrey <kuzinandrey@yandex.ru> 2025-11-04
Home:
   https://github.com/KuzinAndrey/nfqknock
Examples:
  ./nfqknockd -p 22 -p 443 -t 10 -o abracadabra -c ahalaymahalay -d sha256
  Protect ssh and https port from unknown connections.

  ./nfqknockd -o 123 -c 321 -s
  OPEN: 19161 3854 3145 22494 24404 19309 4462 13191
  CLOSE: 3116 25580 8203 7196 17537 13124 20176 1285
  Show port knock sequences for use in shell scripts to open/close protected ports.
```

## Configure SSH client

Use script `nfqknockd_ssh_wrapper` for wrap SSH connection to use port-knocking for open and close protected port.
Place it in on of `$PATH` directory, for example `$HOME/.local/bin` in my case:

```sh
echo $PATH
/home/avkuzin/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

cp nfqknockd_ssh_wrapper $HOME/.local/bin/
chmod +x $HOME/.local/bin/nfqknockd_ssh_wrapper
```
By default in this example script open secret '123' and close secret '321', don't forget change it for your needs.

Create new record in `$HOME/.ssh/config` for protected host:
```
Host develop1
    HostName 10.168.1.17
    User root
    Port 2222
    ProxyCommand sh -c "nfqknockd_ssh_wrapper %h %p"
    IdentityFile ~/.ssh/id_rsa
```

After that run on target host `nfqknockd` daemon by running command:
```sh
sudo nfqknockd -t 10 -p 2222 -o 123 -c 321
```
