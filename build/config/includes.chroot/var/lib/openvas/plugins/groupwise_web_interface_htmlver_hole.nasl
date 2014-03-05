# OpenVAS Vulnerability Test
# $Id: groupwise_web_interface_htmlver_hole.nasl 17 2013-10-27 14:01:43Z jan $
# Description: GroupWise Web Interface 'HTMLVER' hole
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
tag_summary = "By modifying the GroupWise Web Interface HTMLVER URL
request, it is possible to gain additional information on
the remote computer and even read local files from its
hard drive";

tag_solution = "contact your vendor for a patch";

if(description)
{
 script_id(10873);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-0341");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "GroupWise Web Interface 'HTMLVER' hole";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "GroupWise Web Interface 'HTMLVER' hole";
 
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
  if (("Could not find file SYS" >< buf))
  {
   	security_warning(port:port);
	return(1);
  }
  return(0);
}

port = get_http_port(default:80);


cginameandpath[0] = string("/GW5/GWWEB.EXE?GET-CONTEXT&HTMLVER=AAA");
cginameandpath[1] = string("/GWWEB.EXE?GET-CONTEXT&HTMLVER=AAA");


i = 0;
if(get_port_state(port))
{
 for (i = 0; cginameandpath[i]; i = i + 1)
 { 
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}
else exit(0);


foreach dir (cgi_dirs())
{
cginameandpath[0] = string(dir, "/GW5/GWWEB.EXE?GET-CONTEXT&HTMLVER=AAA");
cginameandpath[1] = string(dir, "/GWWEB.EXE?GET-CONTEXT&HTMLVER=AAA");
for (i = 0; cginameandpath[i]; i = i + 1)
 { 
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}
