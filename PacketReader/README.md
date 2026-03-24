# PacketreaderPRO

PacketreaderPRO is a web-based interface for managing and running **Snort 3** in a more user-friendly way. It combines packet inspection, rule management, PCAP replay, live traffic analysis, and alert monitoring in a single dashboard.

## Features

- Run **Snort 3** against live network traffic
- Upload and inspect **PCAP** files
- Manage and edit Snort rules from the web interface
- View alerts in real time
- Store alerts in a local database
- Use a simple web UI instead of only working through the terminal
- Run the stack in Docker for easier setup

## Tech Stack

- **Python**
- **FastAPI**
- **Jinja2**
- **SQLite**
- **Docker / Docker Compose**
- **Snort 3**
- **HTML / CSS / JavaScript**

## Project Structure

```bash
PacketreaderPRO/
└── PacketReader/
    ├── App/
    │   ├── static/
    │   ├── templates/
    │   ├── main.py
    │   ├── database.py
    │   ├── models.py
    │   ├── snort_manager.py
    │   ├── rule_manager.py
    │   └── ...
    ├── docker-compose.yml
    ├── Dockerfile
    └── requirements.txt
What the Application Does

PacketreaderPRO acts as a control panel for Snort 3. Instead of configuring and launching everything manually through the terminal, the application provides a browser-based interface where you can:

start packet analysis
replay uploaded PCAP files
manage rules
inspect generated alerts
monitor results through the dashboard

This makes it easier to test intrusion detection rules and inspect traffic in a more visual way.

Requirements

Before running the project, make sure you have:

Docker
Docker Compose
Python 3.10+ (if running locally without Docker)
A system/environment where Snort 3 can run correctly
Network permissions required for packet capture
Installation
Option 1: Run with Docker

Clone the repository:

git clone https://github.com/HummerZz/PacketreaderPRO.git
cd PacketreaderPRO/PacketReader

Start the application:

docker-compose up --build

After the containers are running, open the application in your browser.

Local Development

If you want to run the web app locally:

Install dependencies:

pip install -r requirements.txt

Start the application:

uvicorn App.main:app --reload

Then open the local FastAPI app in your browser.

Usage

Typical workflow:

Start the application
Open the web dashboard
Choose whether to inspect live traffic or upload a PCAP file
Configure or edit Snort rules
Run analysis
Review alerts and packet inspection results in the interface
Main Components
main.py

Entry point for the FastAPI application. Handles routes, views, and app startup.

snort_manager.py

Responsible for launching and controlling Snort-related operations.

rule_manager.py

Handles rule editing and rule file management.

database.py

Manages database connections and alert storage.

models.py

Defines the application data models.

templates/

Contains the HTML templates used by the web interface.

static/

Contains CSS, JavaScript, and other frontend assets.

Possible Use Cases
Learning how Snort rules work
Testing IDS rules against PCAP samples
Running simple intrusion detection experiments in a lab environment
Reviewing alerts from captured traffic in a cleaner interface
Building a more visual workflow around Snort 3
Notes
This project is intended for educational, lab, and development use unless further hardened for production
Packet capture may require elevated permissions depending on your environment
Snort configuration and interface selection must match your local setup
Docker support simplifies setup, but host networking and permissions still matter for live capture
