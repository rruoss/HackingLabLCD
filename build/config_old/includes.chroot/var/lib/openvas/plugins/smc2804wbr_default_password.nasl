# OpenVAS Vulnerability Test
# $Id: smc2804wbr_default_password.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SMC2804WBR Default Password
#
# Authors:
# Audun Larsen <larsen@xqus.com>
#
# Copyright:
# Copyright (C) 2004 Audun Larsen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host is a SMC2804WBR access point.

This host is installed with a default administrator 
password (smcadmin) which has not been modifed.

An attacker may exploit this flaw to gain control over
this host using the default password.";

tag_solution = "Change the administrator password";

if(description)
{
 script_id(12069);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 name = "SMC2804WBR Default Password";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Logs in with default password on SMC2804WBR";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Audun Larsen");
 family = "Privilege escalation";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if("SMC2804WBR" >< res && "Please enter correct password for Administrator Access. Thank you." >< res)
 {

  host = get_host_name();
  variables = string("page=login&pws=smcadmin");
  req = string("POST /login.htm HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  if("<title>LOGIN</title>" >< buf)
  {
  } else {
   security_hole(port);
   exit(0);
  } 
}

