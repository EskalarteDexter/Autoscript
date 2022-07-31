#!/bin/bash

cat <<'EOFa' > /usr/sbin/sshws.sh
#!/bin/bash
nohup python PDirect.py > /dev/null 2>&1 &
nohup python Proxy.py > /dev/null 2>&1 &
EOFa
chmod +x /usr/sbin/sshws.sh

cat <<'EOFb' > /usr/sbin/sslws.sh
#!/bin/bash
nohup python PStunnel.py > /dev/null 2>&1 &
EOFb
chmod +x /usr/sbin/sslws.sh

cat <<'EOFc' > /usr/sbin/ovpnws.sh
#!/bin/bash
nohup python POpenvpn.py > /dev/null 2>&1 &
EOFc
chmod +x /usr/sbin/ovpnws.sh

cat <<'EOFOne' > /etc/systemd/system/sshws.service
[Unit]
Description=sshws service
Documentation=https://google.com
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
WorkingDirectory=/usr/sbin
ExecStart=/bin/bash /usr/sbin/sshws.sh
ProtectSystem=true
ProtectHome=true
RemainAfterExit=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOFOne

cat <<'EOFTwo' > /etc/systemd/system/sslws.service
[Unit]
Description=sslws service
Documentation=https://google.com
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
WorkingDirectory=/usr/sbin
ExecStart=/bin/bash /usr/sbin/sslws.sh
ProtectSystem=true
ProtectHome=true
RemainAfterExit=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOFTwo

cat <<'EOFThree' > /etc/systemd/system/ovpnws.service
[Unit]
Description=ovpnws service
Documentation=https://google.com
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
WorkingDirectory=/usr/sbin
ExecStart=/bin/bash /usr/sbin/ovpnws.sh
ProtectSystem=true
ProtectHome=true
RemainAfterExit=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOFThree