# deployDev – Device deployment Manager

# requiemets: 
- dedicated Ubuntu Linux host<br>




# unattended installation<br>
    curl -sSL https://raw.githubusercontent.com/airani051346/deployDev/refs/heads/main/install-script.sh | bash

default settings in the script: <br>
• Installation directory:: /opt/network_manager<br>
• Application user: www-data<br>
• port: 443. port 80 is redirected automatically<br>
      
this shell scripts installs all necessary modules and configures necessary permissions. <br>
for the first try self signed certificates are generated <br>


Note: If you don’t have a dedicated host, you can view the raw shell script on GitHub and execute the steps manually..<br>

 
# documentation: Device Deployment Manager - Documentation<br>

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
 ![image](https://github.com/user-attachments/assets/25b32313-1449-473c-b10a-a929a14afdd0)

•	Navigate to the Templates tab<br>
•	Create configuration templates <br>
•	Variable with ascii char only. No – allowed only _<br>
•	enter_expert_mode: and exit_expert_mode: allow to execute commands in the bash shell
    entring and exiting "expert mode" is currently hardcoded in the worker_subrocess.py file. 

 # Template example: 
 ```bash
set hostname {{hostname}}<br>
set interface name WAN ipv4-address {{WAN_IPv4 | default('192.168.178.0')}} subnetmask {{WAN_SUBNET | default('255.255.255.0')}} default gateway {{default_gw | default('192.168.178.1')}}
set interface name LAN1 ipv4-address {{LAN1_IPv4 | default('192.168.178.0')}} subnetmask {{LAN1_SUBNET | default('255.255.255.0')}} 
set interface name LAN2 ipv4-address {{LAN2_IPv4 | default('192.168.178.0')}} subnetmask {{LAN2_SUBNET | default('255.255.255.0')}} 

enter_expert_mode:
ls -al
exit_expert_mode:
show diag
show interfaces table
```

 # Step 2: Add HW Type and define error Keys
 ![image](https://github.com/user-attachments/assets/a7ef3df2-9a18-43af-8552-84a0d561840b)
define a name and add err keys to stop pcecessing lines if it appears in the output of any line that has been<br>
executed.
example: "permission\\s*denied"       where the \\s* represents space in between the two words.

 # Step 3: Add Networks to Scan
![image](https://github.com/user-attachments/assets/c13f6315-616a-429a-ab81-3dbca94ba242)


If you don’t want to use nmap to scan your network please go to step 3<br>
•	Go to the Networks tab<br>
•	Enter a CIDR (e.g. 192.168.1.0/24) or IP range (e.g. 192.168.1.10-192.168.1.50)<br>
•	interval in seconds is under construction <br>
•	Start scanning to discover devices<br>


 # Step 4: Review Discovered Devices
 ![image](https://github.com/user-attachments/assets/2f55be2b-149f-40a1-989c-2f0a1890fc04)

•	Open the Discovered tab<br>
•	Newly found or imported devices appear with status discovered<br>
•	Assign a hardware type and template to each device<br>
Note: visible variables are the predefined in your selected template<br>
•	Optionally, use the Import CSV feature for bulk additions<br>
you can either use a csv file to import devices with following structure:<br>
```csv
192.168.1.10,embedded,Spark-PTK
192.168.1.20,full,Spark-SD-WAN
```
Where the first entry is the ip, second Hardware-type and third used template.<br>
Or use an API call which is more enhanced.<br>
```API
URL: http://<your-server>:5000/app/discovered
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
```
 
 # Step 5: Apply Variables
 ![image](https://github.com/user-attachments/assets/cfb12798-63ac-46cf-85c4-975ce4898a37)

•	Apply Template,  Each template may require variables (e.g. hostname, interface_ip)<br>
•	Apply HW Type<br>
•	define Varianle values 
•	select credentials and expert credentials as needed<br>

You can import the devices over CSV File. see below

 # Step 6: Create Workers
•	Once a device is ready, click Create Worker<br>
•	The system stores the rendered configuration<br>
•	Device status changes to claimed<br>

 # Step 7: Start Worker Execution<br>
 ![image](https://github.com/user-attachments/assets/982ce36c-b22f-44ea-95b1-8a596954b55a)

•	Switch to the Workers tab<br>
•	Click Start Configuration<br>
•	SSH connects to the device and runs each line<br>
•	Output is streamed live with color-coded feedback<br>
•	If an error keyword is matched, execution halts<br>
 # Step 8: Monitor and Debug
•	Use View Log or Stream Log to monitor output<br>
•	Failed tasks show error message and stop line<br>
•	Restart or fix variables and try again if needed<br>

 # Step 9: Cleanup or Finalize
•	Stop or delete workers if needed<br>
•	Device status will become finished, failed, or stopped<br>
 
________________________________________
 # Directory Structure
```treeview
/opt/network_manager/
├── app/             # Flask app
├────backend/        # here is the model 
├──certs             # web front ssl certificates
├──templates         # web front 
├────css             # styles 
├────js              # java script
├──zero_touch.db     # SQLite database
```
# error keyword 

each HW-type can have its ohn error code/word definition. these words are used to stop proccessing the stored conifuration as sson as they appear on output.
```csv
"invalid",    "error",    "failed",    "permission\\s*denied",    "command\\s*not\\s*found",    "not\\s*recognized",    "cannot",    "denied",    "Bad\\s*parameter"
```

a restart will try to reexecute the same line again. In case you want to skipp that line, admin has to increase the value of line Nr in database.

check last line Nr: 
    sqlite3 zero_touch.db "select last_line from workers where id=1"; 

set new line nR to continue with:
    sqlite3 zero_touch.db "UPDATE workers SET last_line = 3 WHERE id = 1;"




________________________________________
 # REST APIs
```
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

____________________________________
# Configuration Files
error_keywords.json.<HW type><br>
```Json
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
```
# CSV Import Format
```csv
192.168.1.10,embedded,Spark-PTK
192.168.1.20,full,Spark-SD-WAN
```
________________________________________
 # Known Limitations
•	Does not support SSH key auth (only username/password)<br>
•	No role-based access or user login<br>
•	Execution assumes reachable devices<br>

