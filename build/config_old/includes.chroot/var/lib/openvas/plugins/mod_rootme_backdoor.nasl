# OpenVAS Vulnerability Test
# $Id: mod_rootme_backdoor.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache mod_rootme Backdoor
#
# Authors:
# Noam Rathaus and upgraded by Alexei Chicheev for mod_rootme v.0.3 detection 
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus and upgraded (15.03.2005) by Alexei Chicheev for mod_rootme v.0.3 detection
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
tag_summary = "The remote system appears to be running the mod_rootme module,
this module silently allows a user to gain a root shell access
to the machine via HTTP requests.";

tag_solution = "- Remove the mod_rootme module from httpd.conf/modules.conf
- Consider reinstalling the computer, as it is likely to have been 
compromised by an intruder";

if(description)
{
  script_id(13644);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-1999-0660");
  name = "Apache mod_rootme Backdoor";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
 
  summary = "Detect mod_rootme Backdoor";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus and upgraded (15.03.2005) by Alexei Chicheev for mod_rootme v.0.3 detection");

  family = "Malware";
  script_family(family);
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (! port) exit(0);

if ( report_paranoia < 2 )
{
 banner = get_http_banner(port:port);
 if ( ! banner || "Apache" >!< banner ) exit(0);
}

if(!get_port_state(port))exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded" ) ) exit(0);

soc = open_sock_tcp(port);
if (soc)
{
 # Syntax for this Trojan is essential... normal requests won't work...
 # We need to emulate a netcat, slow sending, single line each time, unlike HTTP that can
 # receive everything as a block
 send(socket:soc, data:string("GET root HTTP/1.0\n",
                              "Host: ", get_host_name(),"\r\n"));
 sleep(1);
 send(socket:soc, data:string("\n"));
 sleep(1);
 res_vx = recv(socket:soc, length:1024);
 if ( ! res_vx ) exit(0);
 send(socket:soc, data:string("id\r\n",
                              "Host: ", get_host_name(), "\r\n"));
 res = recv(socket:soc, length:1024);
 if (res == NULL) exit(0);
 if (ereg(pattern:"^uid=[0-9]+\(root\)", string:res) && ereg(pattern:"^rootme-[0-9].[0-9] ready", string:res_vx))
 {
  send(socket:soc, data:string("exit\r\n",
                               "Host: ", get_host_name(), "\r\n")); # If we don't exit we can cause Apache to crash
  security_hole(port:port);
 }
 close(soc);
}

