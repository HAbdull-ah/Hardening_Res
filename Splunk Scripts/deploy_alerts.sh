#!/bin/bash

sudo mkdir -p /opt/splunk/etc/apps/search/local

cat << 'EOF' > /opt/splunk/etc/apps/search/local/savedsearches.conf

[SSH Failed Logins]
search = (index=main sourcetype=linux_secure "Failed Password") OR (index=main sourcetype=linux_auth "Failed Password") | rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})" | sort 0 _time | stats count AS failed_count by host, src_ip | where failed_count > 5 description = detects 
SSH brute-force attempts of 5+ failures within 2 minutes cron_schedule = */1 * * * *

dispatch.earliest_time = -5m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:ssh_failed
action.logevent.param.source = ssh_failed_alert
action.logevent.param.event = SSH FAILED LOGIN ALERT: host=$result.host$, failed_count=$result.failed_count$, src_ip=$result.src_ip$
disabled = false

[RDP Failed Logins]
search = index=main sourcetype=WinEventLog:Security EventCode=4625 (Logon_Type=10 OR Logon_Type=3) | eval src_ip=Source_Network_Address | sort 0 _time | stats count AS failed_count by host, src_ip | where failed_count >= 5
description = detects RDP brute-force attempts of 5+ failures within 2 minutes
cron_schedule = */1 * * * *

dispatch.earliest_time = -5m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:rdp_failed
action.logevent.param.source = rdp_failed_alert
action.logevent.param.event = RDP FAILED LOGIN ALERT: host=$result.host$, failed_count=$result.failed_count$, src_ip=$result.src_ip$
disabled = false

[Linux User Created]
search = index=main (sourcetype=linux_secure OR sourcetype=linux_auth) (useradd OR adduser) | rex "name=(?<new_user>[^,]+)" | stats earliest(_time) as time by host new_user
description = Detects creation of new local Linux users via useradd/adduser
cron_schedule = */1 * * * *

dispatch.earliest_time = -2m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:linux_user_created
action.logevent.param.source = linux_user_alert
action.logevent.param.event = NEW LINUX USER ALERT: host=$result.host$, user=$result.new_user$
disabled = false

[Windows User Created]
search = index=main sourcetype=WinEventLog:Security EventCode=4720 | eval new_user=SAM_Account_Name, creator=Account_Name
description = Detects creation of new local Windows users via Event code 4720
cron_schedule = */1 * * * *

dispatch.earliest_time = -2m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:windows_user_created
action.logevent.param.source = windows_user_alert
action.logevent.param.event = NEW WINDOWS USER ALERT: host=$result.host$, new_user=$result.new_user$, creator=$result.creator$
disabled = false

[Linux Privilege Escalation]
search = index=main (sourcetype=linux_secure OR sourcetype=linux_auth) ("added to group" OR "usermod" OR "gpasswd") ("sudo" OR "wheel") | rex field=_raw "add '?(?<added_user>[^']+)'? to group '?(?<target_group>sudo|wheel)'?" | stats count by host added_user target_group
description = Detects when users are added to sudo or wheel in Linux
cron_schedule = */1 * * * *

dispatch.earliest_time = -2m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:linux_privilege_escalation
action.logevent.param.source = linux_escalation_alert
action.logevent.param.event = NEW LINUX ESCALATION ALERT: host=$result.host$, added_user=$result.added_user$, group=$result.target_group$
disabled = false

[Windows Privilege Escalation]
search = index=main sourcetype=WinEventLog:Security (EventCode=4732 OR EventCode=4728)
description = Detects when users are added to Administrator in Windows
cron_schedule = */1 * * * *

dispatch.earliest_time = -2m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:windows_privilege_escalation
action.logevent.param.source = windows_escalation_alert
action.logevent.param.event = NEW WINDOWS ESCALATION ALERT: host=$result.host$, EventCode=$result.EventCode$
disabled = false

[Cron Activity]
search = index=main (sourcetype=linux_messages OR sourcetype=linux_cron) ("CRON" OR "CROND") | rex "\((?<user>[^\)]+)\)\s+CMD\s+\((?<command>.+)\)" | table _time host user command
description = Detects when there is new cron activity in Ubuntu/Oracle Linux
cron_schedule = */1 * * * *

dispatch.earliest_time = -2m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:linux_cron
action.logevent.param.source = linux_cron_alert
action.logevent.param.event = NEW LINUX CRON ALERT: host=$result.host$, user=$result.user$, command=$result.command$
disabled = false

[Windows Service Created]
search = index=main sourcetype=WinEventLog:System EventCode=7045 | table _time host Service_Name Service_File_Name Service_Type Service_Account
description = Detects when a new Windows service is created
cron_schedule = */1 * * * *

dispatch.earliest_time = -2m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:windows_service
action.logevent.param.source = windows_service_alert
action.logevent.param.event = NEW WINDOWS SERVICE ALERT: host=$result.host$, service_name=$result.Service_Name$, service_file=$result.Service_File_Name$, created_by=$result.User$, service_type=$.Service_Type$, run_as=$result.Service_Account$
disabled = false

[Linux Outbound Connections]
search = index=main (sourcetype=linux_auth OR sourcetype=linux_messages) ("COMMAND=") | table _time host USER COMMAND
description = Detects outbound connections on linux: wc, curl, nc, netstat, ssh
cron_schedule = */1 * * * *

dispatch.earliest_time = -2m
dispatch.latest_time = now

#alert_type = number of events
#alert_comparator = greater than
#alert_threshold = 0
counttype = number of events
relation = greater than
quantity = 0
alert.suppress = 0

enableSched = 1
#is_scheduled = 1

action.logevent.param.index = _internal
action.logevent = 1
action.logevent.param.sourcetype = alert:linux_outbound
action.logevent.param.source = linux_outbound_alert
action.logevent.param.event = NEW LINUX OUTBOUND ALERT: host=$result.host$, user=$result.USER$, command=$result.COMMAND$
disabled = false

'EOF'