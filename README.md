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
 
<img width="1772" height="774" alt="image" src="https://github.com/user-attachments/assets/009b9af0-3aa7-4090-b5f7-f16db8c0395e" />

•	Navigate to the Templates tab<br>
•	Create configuration templates <br>

in the template you can define variables: <br>
    it can be just a variable without a default value. for eg:  {{name}}<br>
    or including a default value. for eg: {{lan1_name | default('eth1-01')}}<br>
<br>
special controls: <br>
```cmd
!CONTROL: enter_expert_mode  <br>
after this control you can add something like: <br>
     {"cmd": "expert", "expect": "Password:", "send_username": false, "prompt_success": "#"}
     this sends a command expert to the host on prompt it doe not wait for the username input but for the password. and waits for the prompt including #
     
     {"cmd": "ena", "expect": "login:", "send_username": true, "expect2": "Password:", "prompt_success": "#"}
     this sends a command ena to the host on prompt it waits for the username and for the password. and waits for the prompt including #
```
```cmd
!CONTROL: end_expert_commands
    this prompt to to exit the proviliged mode
    you can add a short sequense to follow
    eg: {"cmd": "exit", "prompt_success": ">"}
```
```cmd
   
!PROMPT:
    wait for the prompt.
    eg:  \[Expert@.*\]# 
```

 ## Template example: 
following template includes by purpose invalid commands to show the error keyword feature. but the structure is valid.
 ```bash
set hostname {{hostname}}
show interfaces table
set interface {{lan1_name | default('eth1-01')}} ipv4-adddress {{lan1_ipv4 | default ('10.1.1.9')}} mask-length {{lan1_masklen | default ('24')}}
set interface {{lan2_name | default('eth1')}} ipv4-adddress {{lan2_ipv4 | default ('10.1.1.9')}} mask-length {{lan2_masklen | default ('24')}}
set interface {{lan3_name | default('vti')}} ipv4-adddress {{lan3_ipv4 | default ('10.1.1.9')}} mask-length {{lan3_masklen | default ('24')}}
!CONTROL: enter_expert_mode {"cmd": "expert", "expect": "Password:", "send_username": false, "prompt_success": "#"}
!PROMPT: \[Expert@.*\]#
ls -al /storage
!CONTROL: end_expert_commands {"cmd": "exit", "prompt_success": ">"}
show diag
```

 # Step 2: Add HW Type and define error Keys
 <img width="1800" height="602" alt="image" src="https://github.com/user-attachments/assets/77652bcf-72fc-4d52-a51e-6e48abe5243b" />

define a name and add err keys to stop pcecessing lines if it appears in the output of any line that has been<br>
executed.
example: "permission\\s*denied"       where the \\s* represents space in between the two words.

 # Step 3: Add Networks to Scan
<img width="1795" height="444" alt="image" src="https://github.com/user-attachments/assets/b4d86ffc-43ae-48d8-87f8-5a05e992a8ae" />

If you don’t want to use nmap to scan your network please go to step 3<br>
•	Go to the Networks tab<br>
•	Enter a CIDR (e.g. 192.168.1.0/24) or IP range (e.g. 192.168.1.10-192.168.1.50)<br>
•	interval in seconds is under construction <br>
•	Start scanning to discover devices<br>

 # Step 4: Review Discovered Devices
 <img width="1893" height="586" alt="image" src="https://github.com/user-attachments/assets/21895fcb-f80b-49bc-969c-8f854e0bcde3" />

•	Open the Discovered tab<br>
•	Newly found or imported devices appear with status discovered<br>
click edit to:
•	Assign a hardware type and template to each device<br>
Note: your template variables appear on template change<br>
<img width="786" height="508" alt="image" src="https://github.com/user-attachments/assets/2b36e802-608b-40b3-8b5f-b026d93509e8" />

•	Optionally, use the Import CSV feature or API for bulk import<br>

csv file with following structure:<br>
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
 
•	define Varianle values 
•	select credentials and expert credentials as needed<br>

 # Step 6: Create Workers
•	Once a device is ready, click Create Worker<br>
•	The system stores the rendered configuration<br>
•	Device status changes to claimed<br>

 # Step 7: Start Worker Execution<br>
 <img width="1765" height="482" alt="image" src="https://github.com/user-attachments/assets/ece998e1-5513-4a36-a802-dadb0e184148" />

•	Switch to the Workers tab<br>
•	Click Start Configuration<br>
•	SSH connects to the device and runs each line<br>
<img width="787" height="618" alt="image" src="https://github.com/user-attachments/assets/22861815-cc36-429f-ae96-5b1e5464d2a1" />
•	If an error keyword is matched, execution halts<br>

 # Step 8: Monitor and Debug
•	Use View Log or Stream Log to monitor output<br>
•	Failed tasks show error message and stop line<br>
<img width="785" height="488" alt="image" src="https://github.com/user-attachments/assets/73f773bb-d6fd-4051-a699-1a1a3d916478" />

View logs: sudo journalctl -u zero_touch-api -f
service restart: service zero_touch-api restart

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

each HW-type can have its own error code/word definition. these words are used to stop proccessing the stored conifuration as sson as they appear on output.
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

