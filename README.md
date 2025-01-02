[comment]: # "Auto-generated SOAR connector documentation"
# Falcon Host API

Publisher: Phantom  
Connector Version: 1.0.36  
Product Vendor: CrowdStrike  
Product Name: Falcon Host API  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 3.0.284  

This app allows you to manage indicators of compromise (IOC) and investigate your endpoints on the Falcon Host API

### Configuration variables
This table lists the configuration variables required to operate Falcon Host API. These variables are specified when configuring a Falcon Host API asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**baseurl** |  required  | string | API Base URL
**verify_server_cert** |  required  | boolean | Verify server certificate
**user** |  required  | string | Falcon API User
**key** |  required  | password | Falcon API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[hunt file](#action-hunt-file) - Hunt for a file on the network by querying for the hash  
[hunt domain](#action-hunt-domain) - Get a list of device IDs on which the domain was matched  
[list processes](#action-list-processes) - List processes that have recently used the IOC on a particular device  
[get process detail](#action-get-process-detail) - Retrieve the details of a process that is running or that previously ran, given a process ID  
[get system info](#action-get-system-info) - Get details of a device, given the device ID  
[create alert](#action-create-alert) - Upload one or more indicators that you want CrowdStrike to watch  
[get alert](#action-get-alert) - Get the full definition of one or more indicators that are being watched  
[update alert](#action-update-alert) - Update an indicator that has been uploaded  
[delete alert](#action-delete-alert) - Delete an indicator that is being watched  
[list alerts](#action-list-alerts) - Get a list of uploaded IOCs that match the search criteria  
[list endpoints](#action-list-endpoints) - List all the endpoints/sensors configured on the device  
[set status](#action-set-status) - Set the state of a detection in Falcon Host  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'hunt file'
Hunt for a file on the network by querying for the hash

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash to search | string |  `hash`  `sha256`  `sha1`  `md5` 
**count_only** |  optional  | Get endpoint count only | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.count_only | boolean |  |  
action_result.parameter.hash | string |  `hash`  `sha256`  `sha1`  `md5`  |  
action_result.data.\*.device_id | string |  `falcon device id`  |  
action_result.summary.device_count | numeric |  |  
action_result.message | string |  |    

## action: 'hunt domain'
Get a list of device IDs on which the domain was matched

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to search | string |  `domain` 
**count_only** |  optional  | Get endpoint count only | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.count_only | boolean |  |  
action_result.parameter.domain | string |  `domain`  |  
action_result.data.\*.device_id | string |  `falcon device id`  |  
action_result.summary.device_count | numeric |  |  
action_result.message | string |  |    

## action: 'list processes'
List processes that have recently used the IOC on a particular device

Type: **investigate**  
Read only: **True**

Given a file hash or domain, the action will list all the processes that have either recently connected to the domain or interacted with the file that matches the supplied hash. Use the <b>list endpoints</b> actions to get the device id to run the action on.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | File Hash or Domain to use for searching | string |  `hash`  `sha256`  `sha1`  `md5`  `domain` 
**id** |  required  | Falcon Device ID to search on | string |  `falcon device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.id | string |  `falcon device id`  |  
action_result.parameter.ioc | string |  `hash`  `sha256`  `sha1`  `md5`  `domain`  |  
action_result.data.\*.falcon_process_id | string |  `falcon process id`  |  
action_result.summary | string |  |  
action_result.message | string |  |    

## action: 'get process detail'
Retrieve the details of a process that is running or that previously ran, given a process ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**falcon_process_id** |  required  | Process ID from previous Falcon IOC search | string |  `falcon process id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.falcon_process_id | string |  `falcon process id`  |  
action_result.data.\*.command_line | string |  |  
action_result.data.\*.device_id | string |  `falcon device id`  |  
action_result.data.\*.file_name | string |  `file name`  |  
action_result.data.\*.process_id | string |  `pid`  |  
action_result.data.\*.process_id_local | string |  `pid`  |  
action_result.data.\*.start_timestamp | string |  |  
action_result.data.\*.start_timestamp_raw | string |  |  
action_result.data.\*.stop_timestamp | string |  |  
action_result.data.\*.stop_timestamp_raw | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |    

## action: 'get system info'
Get details of a device, given the device ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Device ID from previous Falcon IOC search | string |  `falcon device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.parameter.id | string |  `falcon device id`  |   0498d1102b23481162ff846d0633e14c 
action_result.data.\*.agent_load_flags | string |  |   3 
action_result.data.\*.agent_local_time | string |  |   2015-07-31T14:07:42.816Z 
action_result.data.\*.agent_version | string |  |   2.0.0010.3005 
action_result.data.\*.bios_manufacturer | string |  |   Phoenix Technologies LTD 
action_result.data.\*.bios_version | string |  |   6.00 
action_result.data.\*.cid | string |  `md5`  |   3f40c380adc74a3187c27252c0227cff 
action_result.data.\*.config_id_base | string |  |   65994752 
action_result.data.\*.config_id_build | string |  |   3005 
action_result.data.\*.config_id_platform | string |  |   3 
action_result.data.\*.device_id | string |  `falcon device id`  |   0498d1102b23481162ff846d0633e14c 
action_result.data.\*.device_policies.prevention.applied | boolean |  |   True 
action_result.data.\*.device_policies.prevention.applied_date | string |  |  
action_result.data.\*.device_policies.prevention.assigned_date | string |  |   2018-03-10T15:39:31.220730539Z 
action_result.data.\*.device_policies.prevention.policy_id | string |  `md5`  |   f81459e0d85b4bc7b3ad14ad40889042 
action_result.data.\*.device_policies.prevention.policy_type | string |  |   prevention 
action_result.data.\*.device_policies.prevention.settings_hash | string |  |   87cb8b2e 
action_result.data.\*.device_policies.sensor_update.applied | boolean |  |   True  False 
action_result.data.\*.device_policies.sensor_update.applied_date | string |  |  
action_result.data.\*.device_policies.sensor_update.assigned_date | string |  |   2018-03-10T15:39:31.220769757Z 
action_result.data.\*.device_policies.sensor_update.policy_id | string |  `md5`  |   62a3908297584c52bdafaa7fdf3c3bdd 
action_result.data.\*.device_policies.sensor_update.policy_type | string |  |   sensor-update 
action_result.data.\*.device_policies.sensor_update.settings_hash | string |  |   65994753|3|2|automatic 
action_result.data.\*.external_ip | string |  `ip`  |   50.18.218.205 
action_result.data.\*.first_seen | string |  |   2018-03-10T15:38:09Z 
action_result.data.\*.group_hash | string |  `sha256`  |   e2a8b394c0e62960747ff5d64a335162b36ba4c5a54ee6499b438b94e5269ae8 
action_result.data.\*.groups | string |  `md5`  |   873560309d1b4686a6cee666575e7a93 
action_result.data.\*.hostname | string |  `host name`  |   TheNarrowSea  CentOS70 
action_result.data.\*.last_seen | string |  |   2018-03-10T15:39:34Z 
action_result.data.\*.machine_domain | string |  `domain`  |   VICTIMNET.local 
action_result.data.\*.major_version | string |  |   6 
action_result.data.\*.meta.version | string |  |   6  106635 
action_result.data.\*.minor_version | string |  |   1 
action_result.data.\*.modified_timestamp | string |  |   2018-03-10T15:40:09Z 
action_result.data.\*.os_version | string |  |   Windows Server 2008 R2  CentOS 7 
action_result.data.\*.ou | string |  |  
action_result.data.\*.platform_id | string |  |   0  3 
action_result.data.\*.platform_name | string |  |   Windows 
action_result.data.\*.policies.\*.applied | boolean |  |   True 
action_result.data.\*.policies.\*.applied_date | string |  |  
action_result.data.\*.policies.\*.assigned_date | string |  |   2018-03-10T15:39:31.220730539Z 
action_result.data.\*.policies.\*.policy_id | string |  `md5`  |   f81459e0d85b4bc7b3ad14ad40889042 
action_result.data.\*.policies.\*.policy_type | string |  |   prevention 
action_result.data.\*.policies.\*.settings_hash | string |  |   87cb8b2e 
action_result.data.\*.product_type | string |  |   3 
action_result.data.\*.product_type_desc | string |  |   Server 
action_result.data.\*.provision_status | string |  |   Provisioned 
action_result.data.\*.release_group | string |  |  
action_result.data.\*.site_name | string |  |   Default-First-Site-Name 
action_result.data.\*.slow_changing_modified_timestamp | string |  |   2018-04-23T22:52:27Z 
action_result.data.\*.status | string |  |   normal 
action_result.data.\*.system_manufacturer | string |  |   VMware, Inc. 
action_result.data.\*.system_product_name | string |  |   VMware Virtual Platform 
action_result.summary.device_count | numeric |  |  
action_result.summary.hostname | string |  `host name`  |   TheNarrowSea 
action_result.message | string |  |   Hostname: TheNarrowSea 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create alert'
Upload one or more indicators that you want CrowdStrike to watch

Type: **contain**  
Read only: **False**

Valid values for the <b>policy</b> parameter are:<ul><li>detect<br>Send a notification when the particular indicator has been detected on a host</li><li>none<br>Take no action when the particular indicator has been detected on a host. This is equivalent to turning the indicator off.</li></ul><br>As of this writing the only valid value for the <b>share_level</b> parameter is <b>red</b>.<br>The <b>expiration</b> parameter is only valid for IP and Domains. As of this writing, if not specified, the Falcon API defaults to 30 days.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Input domain, ip or hash ioc | string |  `hash`  `sha256`  `sha1`  `md5`  `domain`  `ip` 
**policy** |  required  | Enforcement Policy (in case of detection) | string | 
**share_level** |  optional  | Indicator share level | string | 
**expiration** |  optional  | Alert lifetime in days (domains and ips only) | numeric | 
**source** |  optional  | Indicator Originating source | string | 
**description** |  optional  | Indicator description | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.description | string |  |  
action_result.parameter.expiration | numeric |  |  
action_result.parameter.ioc | string |  `hash`  `sha256`  `sha1`  `md5`  `domain`  `ip`  |  
action_result.parameter.policy | string |  |  
action_result.parameter.share_level | string |  |  
action_result.parameter.source | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get alert'
Get the full definition of one or more indicators that are being watched

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Hash, ip or domain IOC to get details of | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.ioc | string |  `ip`  `sha1`  `md5`  `sha256`  `domain`  |  
action_result.data.\*.created_by | string |  |  
action_result.data.\*.created_timestamp | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.expiration_timestamp | string |  |  
action_result.data.\*.modified_by | string |  |  
action_result.data.\*.modified_timestamp | string |  |  
action_result.data.\*.policy | string |  |  
action_result.data.\*.share_level | string |  |  
action_result.data.\*.source | string |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.value | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'update alert'
Update an indicator that has been uploaded

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Hash, ip or domain IOC to update | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 
**policy** |  optional  | Enforcement policy (in case of detection) | string | 
**share_level** |  optional  | Indicator share level | string | 
**expiration** |  optional  | Alert lifetime in days (domains and ips only) | numeric | 
**source** |  optional  | Indicator originating source | string | 
**description** |  optional  | Indicator description | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.description | string |  |  
action_result.parameter.expiration | numeric |  |  
action_result.parameter.ioc | string |  `ip`  `sha1`  `md5`  `sha256`  `domain`  |  
action_result.parameter.policy | string |  |  
action_result.parameter.share_level | string |  |  
action_result.parameter.source | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'delete alert'
Delete an indicator that is being watched

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Hash, ip or domain IOC from previous upload | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.ioc | string |  `ip`  `sha1`  `md5`  `sha256`  `domain`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'list alerts'
Get a list of uploaded IOCs that match the search criteria

Type: **investigate**  
Read only: **True**

The list of IOCs are segregated by the ioc type in the action results. The action view will limit the display of each IOC type to 100, however the result will contian the complete list returned by the device.<br>Valid and default values for parameters are:<ul><li>type<ul><li>all<br>Search in all IOC types. This is the default</li><li>hash<br>Search for match of type sha256, sha1 and md5</li><li>ipv4</li><li>sha256</li><li>sha1</li><li>md5</li><li>domain</li></ul></li><li>policy<br>Please see the documentation of the <b>create alert</b> action for an explaination of the policy values<ul><li>all<br>This is the default</li><li>detect</li><li>none<br>This is a valid string value for the policy parameter</li></ul></li><li>share_level<ul><li>all<br>This is the default</li><li>red</li></ul></li></ul><br>Every alert has an expiration time set (configured date and time when the alert will expire), use the <b>from_expiration</b> and <b>to_expiration</b> fields to return the alerts whose expiration time and date falls within the specified range. For e.g. to list all the alerts that expire between 1st August 2016 to 1st September 2016 use the from and to expiration dates as 2016-08-01T00:00:00Z and 2016-09-01T00:00:00Z respectively.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  optional  | Hash, ip or domain IOC to match | string |  `hash`  `ip`  `sha1`  `md5`  `sha256`  `domain` 
**type** |  optional  | Indicator type | string | 
**policy** |  optional  | Enforcement policy | string | 
**share_level** |  optional  | Indicator share level | string | 
**source** |  optional  | The source of indicators | string | 
**from_expiration** |  optional  | The earliest indicator expiration date (RFC3339) | string | 
**to_expiration** |  optional  | The latest indicator expiration date (RFC3339) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.from_expiration | string |  |  
action_result.parameter.ioc | string |  `hash`  `ip`  `sha1`  `md5`  `sha256`  `domain`  |  
action_result.parameter.ph | string |  |  
action_result.parameter.policy | string |  |  
action_result.parameter.share_level | string |  |  
action_result.parameter.source | string |  |  
action_result.parameter.to_expiration | string |  |  
action_result.parameter.type | string |  |  
action_result.data.\*.domain | string |  `domain`  |  
action_result.data.\*.ip | string |  `ip`  |  
action_result.data.\*.md5 | string |  `hash`  `md5`  |  
action_result.data.\*.sha1 | string |  `hash`  `sha1`  |  
action_result.data.\*.sha256 | string |  `hash`  `sha256`  |  
action_result.summary.alerts_found | numeric |  |  
action_result.summary.total_domain | numeric |  |  
action_result.summary.total_ip | numeric |  |  
action_result.summary.total_md5 | numeric |  |  
action_result.summary.total_sha1 | numeric |  |  
action_result.summary.total_sha256 | numeric |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

<b>Filtering:</b><br>The Filter parameter allows you to search for specific devices in your environment by platform, host name, IP, or a number of other parameters. The filter must be made in the format FIELD: ’VALUE’.  The value for the field must be a string enclosed by single quotes:<br><code>platform_name:'Windows'</code><br><br>Some numerical fields support filtering with operators. Supported operators include: >, <, =, >=, <=, and != . Using filter operators, it is possible to conduct searches like; show me all devices that have been active in the 7 days before July 31 2016:<br><code>last_seen:>'2016-07-24'</code><br><br>Wildcards are also supported for host name search. For example, you could do a partial search for a device called "my-host-name" like so:<br><code>hostname:'my-host-na\*'</code><br><br>You can also use multiple filter statements, the filters are applied sequentially, each search is executed and then the subsequent search is done over the filtered results. <br>There are two logical operators, a plus sign (+) is used for AND, and comma separated statements in brackets ([,]) are used for OR.   Using logical operators, it is possible to conduct searches like; show me all devices that have been active in the 7 days before July 31 2016 AND devices where the platform is Windows OR Mac:<br><code>last_seen:>'2016-07-24'+platform_name:['Windows','Mac']</code>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**offset** |  optional  | Offset in list of endpoints | numeric | 
**limit** |  optional  | Max endpoints | numeric | 
**filter** |  optional  | Filter to limit endpoints | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.parameter.filter | string |  |  
action_result.parameter.limit | string |  |  
action_result.parameter.offset | string |  |  
action_result.data.\*.agent_load_flags | string |  |   0 
action_result.data.\*.agent_local_time | string |  |   2018-03-22T16:38:22.750Z 
action_result.data.\*.agent_version | string |  |   2.27.1804.0 
action_result.data.\*.bios_manufacturer | string |  |   Phoenix Technologies LTD 
action_result.data.\*.bios_version | string |  |   6.00 
action_result.data.\*.cid | string |  `md5`  |   3f40c380adc74a3187c27252c0227cff 
action_result.data.\*.config_id_base | string |  |   65994753 
action_result.data.\*.config_id_build | string |  |   1804 
action_result.data.\*.config_id_platform | string |  |   8 
action_result.data.\*.device_id | string |  `falcon device id`  |   bfb4ebc6bca04c97592e4f69003aee40 
action_result.data.\*.device_policies.global_config.applied | boolean |  |   True  False 
action_result.data.\*.device_policies.global_config.applied_date | string |  |   2018-03-14T00:09:10.673728368Z 
action_result.data.\*.device_policies.global_config.assigned_date | string |  |   2018-03-14T00:06:29.224753262Z 
action_result.data.\*.device_policies.global_config.policy_id | string |  `md5`  |   d4dd68c990ee40bca1d5ed56b07cdde6 
action_result.data.\*.device_policies.global_config.policy_type | string |  |   globalconfig 
action_result.data.\*.device_policies.global_config.settings_hash | string |  |   614387e8 
action_result.data.\*.device_policies.prevention.applied | boolean |  |   True  False 
action_result.data.\*.device_policies.prevention.applied_date | string |  |   2017-07-27T09:37:31.945581204Z 
action_result.data.\*.device_policies.prevention.assigned_date | string |  |   2017-07-27T09:35:32.555314541Z 
action_result.data.\*.device_policies.prevention.policy_id | string |  `md5`  |   f81459e0d85b4bc7b3ad14ad40889042 
action_result.data.\*.device_policies.prevention.policy_type | string |  |   prevention 
action_result.data.\*.device_policies.prevention.settings_hash | string |  |   87cb8b2e 
action_result.data.\*.device_policies.sensor_update.applied | boolean |  |   True  False 
action_result.data.\*.device_policies.sensor_update.applied_date | string |  |  
action_result.data.\*.device_policies.sensor_update.assigned_date | string |  |   2018-04-23T22:07:05.888228775Z 
action_result.data.\*.device_policies.sensor_update.policy_id | string |  `md5`  |   9d4fd29a70a34612b34157db8b5a5b6d 
action_result.data.\*.device_policies.sensor_update.policy_type | string |  |   sensor-update 
action_result.data.\*.device_policies.sensor_update.settings_hash | string |  |   65994753|8|2|automatic 
action_result.data.\*.external_ip | string |  `ip`  |   50.254.133.53 
action_result.data.\*.first_seen | string |  |   2017-03-28T10:49:06Z 
action_result.data.\*.group_hash | string |  `sha256`  |   e2a8b394c0e62960747ff5d64a335162b36ba4c5a54ee6499b438b94e5269ae8 
action_result.data.\*.groups | string |  `md5`  |   873560309d1b4686a6cee666575e7a93 
action_result.data.\*.hostname | string |  `host name`  |   CentOS70 
action_result.data.\*.last_seen | string |  |   2018-04-23T22:07:06Z 
action_result.data.\*.local_ip | string |  `ip`  |   10.2.18.225 
action_result.data.\*.mac_address | string |  |   00-50-56-9e-34-e4 
action_result.data.\*.machine_domain | string |  `domain`  |   id1.eng.cyphort.com 
action_result.data.\*.major_version | string |  |   3 
action_result.data.\*.meta.version | string |  |   106621 
action_result.data.\*.minor_version | string |  |   10 
action_result.data.\*.modified_timestamp | string |  |   2018-04-23T22:08:19Z 
action_result.data.\*.os_version | string |  |   CentOS 7 
action_result.data.\*.ou | string |  |   Domain Controllers 
action_result.data.\*.platform_id | string |  |   3 
action_result.data.\*.platform_name | string |  |   Linux 
action_result.data.\*.policies.\*.applied | boolean |  |   True  False 
action_result.data.\*.policies.\*.applied_date | string |  |   2017-07-27T09:37:31.945581204Z 
action_result.data.\*.policies.\*.assigned_date | string |  |   2017-07-27T09:35:32.555314541Z 
action_result.data.\*.policies.\*.policy_id | string |  `md5`  |   f81459e0d85b4bc7b3ad14ad40889042 
action_result.data.\*.policies.\*.policy_type | string |  |   prevention 
action_result.data.\*.policies.\*.settings_hash | string |  |   87cb8b2e 
action_result.data.\*.product_type | string |  |   1 
action_result.data.\*.product_type_desc | string |  |   Workstation 
action_result.data.\*.provision_status | string |  |   Provisioned 
action_result.data.\*.release_group | string |  |  
action_result.data.\*.site_name | string |  |   Default-First-Site-Name 
action_result.data.\*.slow_changing_modified_timestamp | string |  |   2018-04-23T22:08:19Z 
action_result.data.\*.status | string |  |   normal 
action_result.data.\*.system_manufacturer | string |  |   VMware, Inc. 
action_result.data.\*.system_product_name | string |  |   VMware Virtual Platform 
action_result.summary.device_count | numeric |  |   100 
action_result.message | string |  |   Device count: 100 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'set status'
Set the state of a detection in Falcon Host

Type: **generic**  
Read only: **False**

The detection <b>id</b> can be obtained from the Crowdstrike UI.<br>Valid values for the <b>state</b> parameter are <i>new</i>, <i>in_progress</i>, <i>true_positive</i>, <i>false_positive</i> and <i>ignored</i>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Detection ID to set the state of | string |  `falcon detection id` 
**state** |  required  | State to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.id | string |  `falcon detection id`  |  
action_result.parameter.state | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  