[comment]: # "Auto-generated SOAR connector documentation"
# Falcon Host API

Publisher: Phantom  
Connector Version: 1\.0\.34  
Product Vendor: CrowdStrike  
Product Name: Falcon Host API  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.284  

This app allows you to manage indicators of compromise \(IOC\) and investigate your endpoints on the Falcon Host API

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Falcon Host API asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**baseurl** |  required  | string | API Base URL
**verify\_server\_cert** |  required  | boolean | Verify server certificate
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
**count\_only** |  optional  | Get endpoint count only | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.count\_only | boolean | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data\.\*\.device\_id | string |  `falcon device id` 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string |   

## action: 'hunt domain'
Get a list of device IDs on which the domain was matched

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to search | string |  `domain` 
**count\_only** |  optional  | Get endpoint count only | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.count\_only | boolean | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.device\_id | string |  `falcon device id` 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string |   

## action: 'list processes'
List processes that have recently used the IOC on a particular device

Type: **investigate**  
Read only: **True**

Given a file hash or domain, the action will list all the processes that have either recently connected to the domain or interacted with the file that matches the supplied hash\. Use the <b>list endpoints</b> actions to get the device id to run the action on\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | File Hash or Domain to use for searching | string |  `hash`  `sha256`  `sha1`  `md5`  `domain` 
**id** |  required  | Falcon Device ID to search on | string |  `falcon device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `falcon device id` 
action\_result\.parameter\.ioc | string |  `hash`  `sha256`  `sha1`  `md5`  `domain` 
action\_result\.data\.\*\.falcon\_process\_id | string |  `falcon process id` 
action\_result\.summary | string | 
action\_result\.message | string |   

## action: 'get process detail'
Retrieve the details of a process that is running or that previously ran, given a process ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**falcon\_process\_id** |  required  | Process ID from previous Falcon IOC search | string |  `falcon process id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.falcon\_process\_id | string |  `falcon process id` 
action\_result\.data\.\*\.command\_line | string | 
action\_result\.data\.\*\.device\_id | string |  `falcon device id` 
action\_result\.data\.\*\.file\_name | string |  `file name` 
action\_result\.data\.\*\.process\_id | string |  `pid` 
action\_result\.data\.\*\.process\_id\_local | string |  `pid` 
action\_result\.data\.\*\.start\_timestamp | string | 
action\_result\.data\.\*\.start\_timestamp\_raw | string | 
action\_result\.data\.\*\.stop\_timestamp | string | 
action\_result\.data\.\*\.stop\_timestamp\_raw | string | 
action\_result\.summary | string | 
action\_result\.message | string |   

## action: 'get system info'
Get details of a device, given the device ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Device ID from previous Falcon IOC search | string |  `falcon device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `falcon device id` 
action\_result\.data\.\*\.agent\_load\_flags | string | 
action\_result\.data\.\*\.agent\_local\_time | string | 
action\_result\.data\.\*\.agent\_version | string | 
action\_result\.data\.\*\.bios\_manufacturer | string | 
action\_result\.data\.\*\.bios\_version | string | 
action\_result\.data\.\*\.cid | string |  `md5` 
action\_result\.data\.\*\.config\_id\_base | string | 
action\_result\.data\.\*\.config\_id\_build | string | 
action\_result\.data\.\*\.config\_id\_platform | string | 
action\_result\.data\.\*\.device\_id | string |  `falcon device id` 
action\_result\.data\.\*\.device\_policies\.prevention\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.prevention\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.prevention\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.settings\_hash | string | 
action\_result\.data\.\*\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.first\_seen | string | 
action\_result\.data\.\*\.group\_hash | string |  `sha256` 
action\_result\.data\.\*\.groups | string |  `md5` 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.last\_seen | string | 
action\_result\.data\.\*\.machine\_domain | string |  `domain` 
action\_result\.data\.\*\.major\_version | string | 
action\_result\.data\.\*\.meta\.version | string | 
action\_result\.data\.\*\.minor\_version | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.os\_version | string | 
action\_result\.data\.\*\.ou | string | 
action\_result\.data\.\*\.platform\_id | string | 
action\_result\.data\.\*\.platform\_name | string | 
action\_result\.data\.\*\.policies\.\*\.applied | boolean | 
action\_result\.data\.\*\.policies\.\*\.applied\_date | string | 
action\_result\.data\.\*\.policies\.\*\.assigned\_date | string | 
action\_result\.data\.\*\.policies\.\*\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.policies\.\*\.policy\_type | string | 
action\_result\.data\.\*\.policies\.\*\.settings\_hash | string | 
action\_result\.data\.\*\.product\_type | string | 
action\_result\.data\.\*\.product\_type\_desc | string | 
action\_result\.data\.\*\.provision\_status | string | 
action\_result\.data\.\*\.release\_group | string | 
action\_result\.data\.\*\.site\_name | string | 
action\_result\.data\.\*\.slow\_changing\_modified\_timestamp | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.system\_manufacturer | string | 
action\_result\.data\.\*\.system\_product\_name | string | 
action\_result\.summary\.device\_count | numeric | 
action\_result\.summary\.hostname | string |  `host name` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create alert'
Upload one or more indicators that you want CrowdStrike to watch

Type: **contain**  
Read only: **False**

Valid values for the <b>policy</b> parameter are\:<ul><li>detect<br>Send a notification when the particular indicator has been detected on a host</li><li>none<br>Take no action when the particular indicator has been detected on a host\. This is equivalent to turning the indicator off\.</li></ul><br>As of this writing the only valid value for the <b>share\_level</b> parameter is <b>red</b>\.<br>The <b>expiration</b> parameter is only valid for IP and Domains\. As of this writing, if not specified, the Falcon API defaults to 30 days\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Input domain, ip or hash ioc | string |  `hash`  `sha256`  `sha1`  `md5`  `domain`  `ip` 
**policy** |  required  | Enforcement Policy \(in case of detection\) | string | 
**share\_level** |  optional  | Indicator share level | string | 
**expiration** |  optional  | Alert lifetime in days \(domains and ips only\) | numeric | 
**source** |  optional  | Indicator Originating source | string | 
**description** |  optional  | Indicator description | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.expiration | numeric | 
action\_result\.parameter\.ioc | string |  `hash`  `sha256`  `sha1`  `md5`  `domain`  `ip` 
action\_result\.parameter\.policy | string | 
action\_result\.parameter\.share\_level | string | 
action\_result\.parameter\.source | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get alert'
Get the full definition of one or more indicators that are being watched

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Hash, ip or domain IOC to get details of | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ioc | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_timestamp | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_timestamp | string | 
action\_result\.data\.\*\.modified\_by | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.policy | string | 
action\_result\.data\.\*\.share\_level | string | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update alert'
Update an indicator that has been uploaded

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Hash, ip or domain IOC to update | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 
**policy** |  optional  | Enforcement policy \(in case of detection\) | string | 
**share\_level** |  optional  | Indicator share level | string | 
**expiration** |  optional  | Alert lifetime in days \(domains and ips only\) | numeric | 
**source** |  optional  | Indicator originating source | string | 
**description** |  optional  | Indicator description | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.expiration | numeric | 
action\_result\.parameter\.ioc | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 
action\_result\.parameter\.policy | string | 
action\_result\.parameter\.share\_level | string | 
action\_result\.parameter\.source | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete alert'
Delete an indicator that is being watched

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  required  | Hash, ip or domain IOC from previous upload | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ioc | string |  `ip`  `sha1`  `md5`  `sha256`  `domain` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list alerts'
Get a list of uploaded IOCs that match the search criteria

Type: **investigate**  
Read only: **True**

The list of IOCs are segregated by the ioc type in the action results\. The action view will limit the display of each IOC type to 100, however the result will contian the complete list returned by the device\.<br>Valid and default values for parameters are\:<ul><li>type<ul><li>all<br>Search in all IOC types\. This is the default</li><li>hash<br>Search for match of type sha256, sha1 and md5</li><li>ipv4</li><li>sha256</li><li>sha1</li><li>md5</li><li>domain</li></ul></li><li>policy<br>Please see the documentation of the <b>create alert</b> action for an explaination of the policy values<ul><li>all<br>This is the default</li><li>detect</li><li>none<br>This is a valid string value for the policy parameter</li></ul></li><li>share\_level<ul><li>all<br>This is the default</li><li>red</li></ul></li></ul><br>Every alert has an expiration time set \(configured date and time when the alert will expire\), use the <b>from\_expiration</b> and <b>to\_expiration</b> fields to return the alerts whose expiration time and date falls within the specified range\. For e\.g\. to list all the alerts that expire between 1st August 2016 to 1st September 2016 use the from and to expiration dates as 2016\-08\-01T00\:00\:00Z and 2016\-09\-01T00\:00\:00Z respectively\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ioc** |  optional  | Hash, ip or domain IOC to match | string |  `hash`  `ip`  `sha1`  `md5`  `sha256`  `domain` 
**type** |  optional  | Indicator type | string | 
**policy** |  optional  | Enforcement policy | string | 
**share\_level** |  optional  | Indicator share level | string | 
**source** |  optional  | The source of indicators | string | 
**from\_expiration** |  optional  | The earliest indicator expiration date \(RFC3339\) | string | 
**to\_expiration** |  optional  | The latest indicator expiration date \(RFC3339\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.from\_expiration | string | 
action\_result\.parameter\.ioc | string |  `hash`  `ip`  `sha1`  `md5`  `sha256`  `domain` 
action\_result\.parameter\.ph | string | 
action\_result\.parameter\.policy | string | 
action\_result\.parameter\.share\_level | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.to\_expiration | string | 
action\_result\.parameter\.type | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.md5 | string |  `hash`  `md5` 
action\_result\.data\.\*\.sha1 | string |  `hash`  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `hash`  `sha256` 
action\_result\.summary\.alerts\_found | numeric | 
action\_result\.summary\.total\_domain | numeric | 
action\_result\.summary\.total\_ip | numeric | 
action\_result\.summary\.total\_md5 | numeric | 
action\_result\.summary\.total\_sha1 | numeric | 
action\_result\.summary\.total\_sha256 | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

<b>Filtering\:</b><br>The Filter parameter allows you to search for specific devices in your environment by platform, host name, IP, or a number of other parameters\. The filter must be made in the format FIELD\: ’VALUE’\.  The value for the field must be a string enclosed by single quotes\:<br><code>platform\_name\:'Windows'</code><br><br>Some numerical fields support filtering with operators\. Supported operators include\: >, <, =, >=, <=, and \!= \. Using filter operators, it is possible to conduct searches like; show me all devices that have been active in the 7 days before July 31 2016\:<br><code>last\_seen\:>'2016\-07\-24'</code><br><br>Wildcards are also supported for host name search\. For example, you could do a partial search for a device called "my\-host\-name" like so\:<br><code>hostname\:'my\-host\-na\*'</code><br><br>You can also use multiple filter statements, the filters are applied sequentially, each search is executed and then the subsequent search is done over the filtered results\. <br>There are two logical operators, a plus sign \(\+\) is used for AND, and comma separated statements in brackets \(\[,\]\) are used for OR\.   Using logical operators, it is possible to conduct searches like; show me all devices that have been active in the 7 days before July 31 2016 AND devices where the platform is Windows OR Mac\:<br><code>last\_seen\:>'2016\-07\-24'\+platform\_name\:\['Windows','Mac'\]</code>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**offset** |  optional  | Offset in list of endpoints | numeric | 
**limit** |  optional  | Max endpoints | numeric | 
**filter** |  optional  | Filter to limit endpoints | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | string | 
action\_result\.parameter\.offset | string | 
action\_result\.data\.\*\.agent\_load\_flags | string | 
action\_result\.data\.\*\.agent\_local\_time | string | 
action\_result\.data\.\*\.agent\_version | string | 
action\_result\.data\.\*\.bios\_manufacturer | string | 
action\_result\.data\.\*\.bios\_version | string | 
action\_result\.data\.\*\.cid | string |  `md5` 
action\_result\.data\.\*\.config\_id\_base | string | 
action\_result\.data\.\*\.config\_id\_build | string | 
action\_result\.data\.\*\.config\_id\_platform | string | 
action\_result\.data\.\*\.device\_id | string |  `falcon device id` 
action\_result\.data\.\*\.device\_policies\.global\_config\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.global\_config\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.global\_config\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.global\_config\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.prevention\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.prevention\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.prevention\.settings\_hash | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.applied | boolean | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.applied\_date | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.assigned\_date | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.policy\_type | string | 
action\_result\.data\.\*\.device\_policies\.sensor\_update\.settings\_hash | string | 
action\_result\.data\.\*\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.first\_seen | string | 
action\_result\.data\.\*\.group\_hash | string |  `sha256` 
action\_result\.data\.\*\.groups | string |  `md5` 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.last\_seen | string | 
action\_result\.data\.\*\.local\_ip | string |  `ip` 
action\_result\.data\.\*\.mac\_address | string | 
action\_result\.data\.\*\.machine\_domain | string |  `domain` 
action\_result\.data\.\*\.major\_version | string | 
action\_result\.data\.\*\.meta\.version | string | 
action\_result\.data\.\*\.minor\_version | string | 
action\_result\.data\.\*\.modified\_timestamp | string | 
action\_result\.data\.\*\.os\_version | string | 
action\_result\.data\.\*\.ou | string | 
action\_result\.data\.\*\.platform\_id | string | 
action\_result\.data\.\*\.platform\_name | string | 
action\_result\.data\.\*\.policies\.\*\.applied | boolean | 
action\_result\.data\.\*\.policies\.\*\.applied\_date | string | 
action\_result\.data\.\*\.policies\.\*\.assigned\_date | string | 
action\_result\.data\.\*\.policies\.\*\.policy\_id | string |  `md5` 
action\_result\.data\.\*\.policies\.\*\.policy\_type | string | 
action\_result\.data\.\*\.policies\.\*\.settings\_hash | string | 
action\_result\.data\.\*\.product\_type | string | 
action\_result\.data\.\*\.product\_type\_desc | string | 
action\_result\.data\.\*\.provision\_status | string | 
action\_result\.data\.\*\.release\_group | string | 
action\_result\.data\.\*\.site\_name | string | 
action\_result\.data\.\*\.slow\_changing\_modified\_timestamp | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.system\_manufacturer | string | 
action\_result\.data\.\*\.system\_product\_name | string | 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'set status'
Set the state of a detection in Falcon Host

Type: **generic**  
Read only: **False**

The detection <b>id</b> can be obtained from the Crowdstrike UI\.<br>Valid values for the <b>state</b> parameter are <i>new</i>, <i>in\_progress</i>, <i>true\_positive</i>, <i>false\_positive</i> and <i>ignored</i>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Detection ID to set the state of | string |  `falcon detection id` 
**state** |  required  | State to set | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `falcon detection id` 
action\_result\.parameter\.state | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 