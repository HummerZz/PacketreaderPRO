Snort Web Console Pro
A lightweight web GUI for running Snort 3 with live capture or PCAP replay.
Features
• Run Snort 3 from a web interface
• Live capture on a selected network interface
• PCAP replay support
• Rule editing in browser
• Live alerts over WebSocket
• Alert history stored in SQLite
• Dashboard with counters and top sources/rules
• Docker-ready for Ubuntu/Linux servers
Intended environment
This project is intended to run on a real Ubuntu/Linux server.
WSL can work for parts of development, but live capture behavior may be delayed or inconsistent there.
For reliable live IDS behavior, run this on:
• Ubuntu server
• Linux VM
• Dedicated Linux sensor host
Project structure
snortkopia/
├── App/
│   ├── app.py
│   ├── index.html
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── data/
│       ├── local.rules
│       ├── output/
│       └── .gitkeep
├── .gitignore
└── README.md
Default paths inside container
• Snort binary: /usr/local/bin/snort
• Rules file: /app/data/local.rules
• Output dir: /app/data/output
Start with Docker
From inside the App folder:
docker compose up –build
Then open:
http://SERVER_IP:8080
Recommended runtime settings
This project is designed to run with:
• network_mode: host
• privileged: true
That allows Snort to access the host network interface directly.
First-time UI config
In the web UI, verify:
• snort_binary = /usr/local/bin/snort
• rules_path = /app/data/local.rules
• output_dir = /app/data/output
• home_net = any
Example rule
alert icmp any any -> any any (msg:“ICMP detected”; sid:1000001; rev:1;)
Manual checks inside container
docker exec -it snort-web /usr/local/bin/snort -V
docker exec -it snort-web ip a
docker exec -it snort-web /usr/local/bin/snort -i eth0 -R /app/data/local.rules -A alert_fast
Notes
• The GUI uses WebSocket live updates.
• Alert history is stored in SQLite in App/data/alerts.db.
• PCAP replay is a good validation path.
• Live capture quality depends on the host Linux environment and interface access.
Troubleshooting
Web UI loads but live capture does not work
Check:
• correct interface name from ip a
• container is running with host networking
• container has required privileges
• Snort works manually inside the container
No alerts in live mode
Try:
• a simple ICMP rule
• generate traffic with ping
• test Snort manually inside the container
• validate with PCAP replay
Verify Snort is installed
docker exec -it snort-web /usr/local/bin/snort -V