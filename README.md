# deployDev – Zero-Touch Deployment Manager

# requiemets: 
- dedicated Ubuntu Linux host<br>
unattended installation<br>
    curl -sSL https://raw.githubusercontent.com/airani051346/deployDev/refs/heads/main/install-script.sh | bash<br>

default settings in the script: <br>
• Installation directory:: /opt/network_manager<br>
• Application user: www-data<br>
• port: 443. port 80 is redirected automatically<br>
      
this shell scripts installs all necessary modules and configures necessary permissions. <br>
for the first try self signed certificates are generated <br>


Note: If you don’t have a dedicated host, you can view the raw shell script on GitHub and execute the steps manually..<br>

 
# documentation: Zero-Touch Deployment Manager - Documentation<br>

# Overview
The solution is a Flask-based web application designed for automated discovery, templating, <br>
and configuration of network devices over SSH. The system includes dynamic templating, <br>
SSH execution with live feedback, credential management, and status tracking.
________________________________________
# Key Features
•	Web-based UI for managing templates, devices, credentials, and worker tasks<br>
•	CIDR/IP-range based scanning using Nmap<br>
•	Discovered device management with dynamic variables<br>
•	Jinja2-based configuration templates with placeholder support<br>
•	SSH-based configuration deployment with stop-keyword logic<br>
•	Live logging via Server-Sent Events (SSE)<br>
•	Credential and expert-mode handling<br>
•	CSV-based bulk import for discovered devices<br>
________________________________________
 
# User Workflow
 # Step 1: Define Templates
 
•	Navigate to the Templates tab<br>
•	Create configuration templates <br>
•	Variable with ascii char only. No – allowed only _<br>
•	Enter_expert_mode: and exit_expert_mode: allow to execute commands in the bash shell

 # Template example: 
 ```bash
set hostname {{hostname}}<br>
set interface name WAN ipv4-address {{WAN_IPv4 | default('192.168.178.0')}} subnetmask {{WAN_SUBNET | default('255.255.255.0')}} default gateway {{default_gw | default('192.168.178.1')}}<br>
set interface name LAN1 ipv4-address {{LAN1_IPv4 | default('192.168.178.0')}} subnetmask {{LAN1_SUBNET | default('255.255.255.0')}} <br>
set interface name LAN2 ipv4-address {{LAN2_IPv4 | default('192.168.178.0')}} subnetmask {{LAN2_SUBNET | default('255.255.255.0')}} <br>
<br>
enter_expert_mode:<br>
ls -al<br>
exit_expert_mode:<br>
show diag<br>
show interfaces table<br>
```
 # Step 2: Add Networks to Scan
 
•	Go to the Networks tab<br>
•	Enter a CIDR (e.g. 192.168.1.0/24) or IP range (e.g. 192.168.1.10-192.168.1.50)<br>
•	interval in seconds is under construction <br>
•	Start scanning to discover devices<br>
If vou don’t want to use nmap to scan your network please go to step 3<br>

 # Step 3: Review Discovered Devices
•	Open the Discovered tab<br>
•	Newly found or imported devices appear with status discovered<br>
•	Assign a hardware type and template to each device<br>
Note: visible variables are the predefined in your selected template<br>
•	Optionally, use the Import CSV feature for bulk additions<br>
you can either use a csv file to import devices with following structure:<br>
192.168.1.10,embedded,Spark-PTK<br>
192.168.1.20,full,Spark-SD-WAN<br>
Where the first entry is the ip, second Hardware-type and third used template.<br>
Or use an API call which is more enhanced.<br>
```API
•	http://<your-server>:5000/app/discovered<br>
{<br>
   "ip": "192.168.1.123",<br>
   "name": "lab-device-1",<br>
   "template_id": 3,<br>
   "hw_type": "Fortinet",<br>
   "variables": {<br>
     "hostname": "fw01"<br>
   },<br>
   "status": "discovered"<br>
}<br>
```
 
 # Step 4: Apply Variables
•	Each template may require variables (e.g. hostname, interface_ip)<br>
•	Input these in the UI form or auto-assign from CSV<br>
•	Apply credentials and expert credentials as needed<br>

 # Step 5: Create Workers
•	Once a device is ready, click Create Worker<br>
•	The system stores the rendered configuration<br>
•	Device status changes to claimed<br>

 # Step 6: Start Worker Execution<br>
•	Switch to the Workers tab<br>
•	Click Start Configuration<br>
•	SSH connects to the device and runs each line<br>
•	Output is streamed live with color-coded feedback<br>
•	If an error keyword is matched, execution halts<br>
 # Step 7: Monitor and Debug
•	Use View Log or Stream Log to monitor output<br>
•	Failed tasks show error message and stop line<br>
•	Restart or fix variables and try again if needed<br>

 # Step 8: Cleanup or Finalize
•	Stop or delete workers if needed<br>
•	Device status will become finished, failed, or stopped<br>
 
________________________________________
 # Directory Structure
/opt/network_manager/<br>
├── app/             # Flask app<br>
├──── tmp/           # Temporary workspace<br>
├────backend/        # here is the model<br>
├──────keywords      # Stop-word lists per hardware type <br>
├──certs             # web front ssl certificates<br>
├──templates         # web front <br>
├────css             # styles <br>
├────js              # java script<br> 
├──zero_touch.db     # SQLite database<br>

________________________________________
 # JSON APIs
Template Management<br>
GET  /app/templates<br>
POST /app/templates {name, content}<br>
PUT  /app/templates/<id><br>
DELETE /app/templates/<id><br>

Network Scanning<br>
GET  /app/networks<br>
POST /app/networks {cidr, interval}<br>
POST /app/scan/<id>/start<br>
POST /app/scan/<id>/stop<br>
Device Discovery<br>
GET  /app/discovered<br>
POST /app/discovered {ip, name, template_id, hw_type, variables, status}<br>
DELETE /app/discovered/<id><br>
Worker Handling<br>
POST /app/deploy/<discovered_id><br>
POST /app/workers/<id>/start<br>
POST /app/workers/<id>/stop<br>
GET  /app/worker/<id>/stream<br>
GET  /app/workers/<id>/log<br>
________________________________________
# Configuration Files
error_keywords.json.<HW type><br>
[<br>
  "invalid",<br>
  "error",<br>
  "failed",<br>
  "permission\\s*denied",<br>
  "command\\s*not\\s*found",<br>
  "not\\s*recognized",<br>
  "cannot",<br>
  "denied",<br>
  "unexpected",<br>
  "syntax\\s*error",<br>
  "Bad\\s*parameter"<br>
]<br>

# CSV Import Format
192.168.1.10,embedded,Spark-PTK<br>
192.168.1.20,full,Spark-SD-WAN<br>
________________________________________
 # Known Limitations
•	Does not support SSH key auth (only username/password)<br>
•	No role-based access or user login<br>
•	Execution assumes reachable devices<br>

