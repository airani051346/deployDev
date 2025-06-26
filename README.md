# deployDev
installation
    curl -sSL https://raw.githubusercontent.com/airani051346/deployDev/refs/heads/main/install-script.sh | bash

this shell scripts installs on a new Ubuntu Linux machine all necessary module and script. 

 
# documentation:
Zero-Touch Deployment Manager - Documentation<br>

# Overview
The solution is a Flask-based web application designed for automated discovery, templating, <br>
and configuration of network devices over SSH. The system includes dynamic templating, <br>
SSH execution with live feedback, credential management, and status tracking.
________________________________________
# Key Features
•	Web-based UI for managing templates, devices, credentials, and worker tasks
•	CIDR/IP-range based scanning using Nmap
•	Discovered device management with dynamic variables
•	Jinja2-based configuration templates with placeholder support
•	SSH-based configuration deployment with stop-keyword logic
•	Live logging via Server-Sent Events (SSE)
•	Credential and expert-mode handling
•	CSV-based bulk import for discovered devices
________________________________________
 
# User Workflow
 # Step 1: Define Templates
 
•	Navigate to the Templates tab
•	Create configuration templates 
o	Variable with ascii char only. No – allowed only _
o	Enter_expert_mode: and exit_expert_mode: allow to execute commands in the bash shell
Template example: 
set hostname {{hostname}}
set interface name WAN ipv4-address {{WAN_IPv4 | default('192.168.178.0')}} subnetmask {{WAN_SUBNET | default('255.255.255.0')}} default gateway {{default_gw | default('192.168.178.1')}}
set interface name LAN1 ipv4-address {{LAN1_IPv4 | default('192.168.178.0')}} subnetmask {{LAN1_SUBNET | default('255.255.255.0')}} 
set interface name LAN2 ipv4-address {{LAN2_IPv4 | default('192.168.178.0')}} subnetmask {{LAN2_SUBNET | default('255.255.255.0')}} 

enter_expert_mode:
ls -al
exit_expert_mode:
show diag
show interfaces table

 # Step 2: Add Networks to Scan
 
•	Go to the Networks tab
•	Enter a CIDR (e.g. 192.168.1.0/24) or IP range (e.g. 192.168.1.10-192.168.1.50)
•	interval in seconds is under construction 
•	Start scanning to discover devices
If vou don’t want to use nmap to scan your network please go to step 3

 # Step 3: Review Discovered Devices
•	Open the Discovered tab
•	Newly found or imported devices appear with status discovered
•	Assign a hardware type and template to each device
Note: visible variables are the predefined in your selected template
•	Optionally, use the Import CSV feature for bulk additions
you can either use a csv file to import devices with following structure:
192.168.1.10,embedded,Spark-PTK
192.168.1.20,full,Spark-SD-WAN
Where the first entry is the ip, second Hardware-type and third used template.
Or use an API call which is more enhanced.
•	http://<your-server>:5000/app/discovered
{
   "ip": "192.168.1.123",
   "name": "lab-device-1",
   "template_id": 3,
   "hw_type": "Fortinet",
   "variables": {
     "hostname": "fw01"
   },
   "status": "discovered"
}

 
 # Step 4: Apply Variables
•	Each template may require variables (e.g. hostname, interface_ip)
•	Input these in the UI form or auto-assign from CSV
•	Apply credentials and expert credentials as needed
Step 5: Create Workers
•	Once a device is ready, click Create Worker
•	The system stores the rendered configuration
•	Device status changes to claimed
Step 6: Start Worker Execution
•	Switch to the Workers tab
•	Click Start Configuration
•	SSH connects to the device and runs each line
•	Output is streamed live with color-coded feedback
•	If an error keyword is matched, execution halts
Step 7: Monitor and Debug
•	Use View Log or Stream Log to monitor output
•	Failed tasks show error message and stop line
•	Restart or fix variables and try again if needed
Step 8: Cleanup or Finalize
•	Stop or delete workers if needed
•	Device status will become finished, failed, or stopped
 
________________________________________
 # Directory Structure
/opt/network_manager/
├── app/             # Flask app
├──── tmp/           # Temporary workspace
├────backend/        # here is the model
├──────keywords      # Stop-word lists per hardware type 
├──certs             # web front ssl certificates
├──templates         # web front 
├────css             # styles 
├────js              # java script 
├──zero_touch.db     # SQLite database

________________________________________
 # JSON APIs
Template Management
GET  /app/templates
POST /app/templates {name, content}
PUT  /app/templates/<id>
DELETE /app/templates/<id>
Network Scanning
GET  /app/networks
POST /app/networks {cidr, interval}
POST /app/scan/<id>/start
POST /app/scan/<id>/stop
Device Discovery
GET  /app/discovered
POST /app/discovered {ip, name, template_id, hw_type, variables, status}
DELETE /app/discovered/<id>
Worker Handling
POST /app/deploy/<discovered_id>
POST /app/workers/<id>/start
POST /app/workers/<id>/stop
GET  /app/worker/<id>/stream
GET  /app/workers/<id>/log
________________________________________
Configuration Files
error_keywords.json (per HW type)
[
  "invalid",
  "error",
  "failed",
  "permission\\s*denied",
  "command\\s*not\\s*found",
  "not\\s*recognized",
  "cannot",
  "denied",
  "unexpected",
  "syntax\\s*error",
  "Bad\\s*parameter"
]
CSV Import Format
192.168.1.10,embedded,Spark-PTK
192.168.1.20,full,Spark-SD-WAN
________________________________________
 # Known Limitations
•	Does not support SSH key auth (only username/password)
•	No role-based access or user login
•	Execution assumes reachable devices



