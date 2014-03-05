# OpenVAS Vulnerability Test
# $Id: gather-hardware-info.nasl 28 2013-10-30 13:28:35Z mime $
# Description: Gather hardware related information
#
# Authors:
# Henri Doreau <henri.doreau@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

include("revisions-lib.inc");
tag_summary = "This script connects to the target and gathers information about its
hardware configuration.";

if(description)
{
 script_id(103996);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 28 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-30 14:28:35 +0100 (Wed, 30 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-04-05 14:24:03 +0200 (Tue, 05 Apr 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Gather hardware info");

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);

 script_summary("Gather hardware related information");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
 script_family("General");
 script_dependencies("gather-package-list.nasl", "find_service.nasl", "ssh_authorization.nasl","gb_wmi_get-dns_name.nasl","netbios_name_get.nasl");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


# -- script entry point -- #

include("ssh_func.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103996";
SCRIPT_DESC = "Gather hardware related information";

# Register hostname, despite this isn't stricly speaking hardware related information
hostname = get_host_name();
if (!isnull(hostname) && hostname != '' && hostname != get_host_ip()) {
    register_host_detail(name:"hostname", value:hostname, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    register_host_detail(name:"DNS-via-TargetDefinition", value:hostname, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

if(hostname == get_host_ip() || hostname == "" || isnull(hostname)) {
  DNS_via_WMI_FQDNS = get_kb_item("DNS-via-WMI-FQDNS");
  if (!isnull(DNS_via_WMI_FQDNS) && DNS_via_WMI_FQDNS != '' && DNS_via_WMI_FQDNS != get_host_ip()) {
    register_host_detail(name:"hostname", value:DNS_via_WMI_FQDNS, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  } else {
    DNS_via_WMI_DNS   = get_kb_item("DNS-via-WMI-DNS");
    if (!isnull(DNS_via_WMI_DNS) && DNS_via_WMI_DNS != '' && DNS_via_WMI_DNS != get_host_ip()) {
      register_host_detail(name:"hostname", value:DNS_via_WMI_DNS, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    } else {
      SMB_HOST_NAME = get_kb_item("SMB/name");
      if (!isnull(SMB_HOST_NAME) && SMB_HOST_NAME != '' && SMB_HOST_NAME != get_host_ip()) {
        register_host_detail(name:"hostname", value:SMB_HOST_NAME, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
      }
    }
  }  
}

if (host_runs("linux") == "no") {
    exit(0);
}

port = get_kb_item("Services/ssh");
if(isnull(port)) {
    port = 22;
}

sock = ssh_login_or_reuse_connection();
if(!sock) {
   exit(0);
}

# -- Get CPU information -- #
cpuinfo = ssh_cmd(socket:sock, cmd:"cat /proc/cpuinfo");
cpus = make_array();
cpunumber = 0;
foreach line (split(cpuinfo)) {

    if (line =~ "^processor")
    	cpunumber++;
    
    v = eregmatch(string:line, icase:1, pattern:"^(model name.*: )(.*).$");
    if (!isnull(v)) {
    	if (isnull(cpus[v[2]])) {
            cpus[v[2]] = 1;
        } else {
            cpus[v[2]]++;
        }
    }
}

# -- Get memory information -- #
meminfo = ssh_cmd(socket:sock, cmd:"cat /proc/meminfo");
memtotal = "";
foreach line (split(meminfo)) {
    v = eregmatch(string:line, icase:1, pattern:"^(MemTotal:[ ]+)([0-9]+ kB).$");
    if (!isnull(v)) {
    	memtotal = v[2];
    	break;
    }
}

# -- Get network interfaces information -- #
ifconfig = ssh_cmd(socket:sock, cmd:"/sbin/ifconfig");

interfaces = split(ifconfig, sep:'\n\n', keep:FALSE);
netinfo = "";

host_ip = get_host_ip();

foreach interface (interfaces) {

  x = 0;
  ip_str = '';

  if("Loopback" >< interface) continue;

  lines = split(interface);

  foreach line (lines) {

    v = eregmatch(string:line, pattern:"^[^ ].*|.*inet[6]? addr.*|^$");
    if (!isnull(v)) {
    	netinfo += v[0];
    }

    if("HWaddr" >< line) {

        mac = eregmatch(pattern:"HWaddr ([0-9a-fA-F:]{17})", string:line);
        nic = eregmatch(pattern:"(^[^ ]+)", string:line);

	z = x + 1;
	while(ip  = eregmatch(pattern:"inet[6]? addr:[ ]?([^ ]+)", string:lines[z])) {
	
	    if(!isnull(ip[1])) {
                ip_str += ip[1] + ';'; 
	    }    
           
	    z++;

	}

	ip_str = substr(ip_str,0, strlen(ip_str)-2);

        if (!isnull(mac)) {

            if( host_ip >< lines[x+1]) {
                register_host_detail(name:"MAC", value:mac[1], nvt:SCRIPT_OID, desc:SCRIPT_DESC);
                if(!isnull(nic[1])) {
                    target_nic = nic[1];
                    register_host_detail(name:"NIC", value:nic[1], nvt:SCRIPT_OID, desc:SCRIPT_DESC);
                    if(strlen(ip_str) > 0) {
                        register_host_detail(name:"NIC_IPS", value:ip_str, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
                    }			
                }		  
            } 

            if(!isnull(nic[1]) && nic[1] != target_nic) {
                register_host_detail(name:"MAC-Ifaces", value:nic[1] + '|' + mac[1] + '|' + ip_str, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
            }		
  	      
        } else {

            iv_mac = eregmatch(pattern:"HWaddr ([^ \n]+)", string:line);
            if(!isnull(iv_mac[1]) && !isnull(nic[1])) {
                register_host_detail(name:"BROKEN_MAC-Iface", value:nic[1] + '|' + iv_mac[1] + '|' + ip_str, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
	    }  

        }	  
    }

    x++;

  }
}


# -- store results in the host details DB -- #
if (cpunumber) {
    cpu_str = '';
    foreach cputype (keys(cpus)) {
    	if (cpu_str != '') {
    	    cpu_str += '\n';
        }
        cpu_str += string(cpus[cputype], " ", cputype);
    }
    register_host_detail(name:"cpuinfo", value:cpu_str, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

if (memtotal != "") {
    register_host_detail(name:"meminfo", value:memtotal, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

if (netinfo != "") {
    register_host_detail(name:"netinfo", value:netinfo, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

exit(0);

