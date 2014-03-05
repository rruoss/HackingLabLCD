# OpenVAS Vulnerability Test
# $Id: sqlqhit_information_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SQLQHit Directory Structure Disclosure
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "The Sample SQL Query CGI is present. 
The sample allows anyone to structure a certain query that would retrieve
the content of directories present on the local server.";

tag_solution = "Use Microsoft's Secure IIS Guide (For IIS 4.0 or IIS 5.0 respectively) or
Microsoft's IIS Lockdown tool to remove IIS samples.

Additional information:
http://www.securiteam.com/tools/5QP0N1F55Q.html (IIS Lookdown)
http://www.securiteam.com/windowsntfocus/5HP05150AQ.html (Secure IIS 4.0)
http://www.securiteam.com/windowsntfocus/5RP0D1F4AU.html (Secure IIS 5.0)";


if(description)
{
 script_id(10765);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3339);
script_cve_id("CVE-2001-0986");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

name = "SQLQHit Directory Structure Disclosure";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "SQLQHit Directory Stracture Disclosure";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "Web application abuses";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");



program[0] = "sqlqhit.asp";
program[1] = "SQLQHit.asp";

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);


foreach dir (cgi_dirs())
{
 for (j = 0; program[j] ; j = j + 1)
 {
  url = string(dir, "/", program[j], "?CiColumns=*&CiScope=webinfo");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  if (("VPATH" >< buf) && ("PATH" >< buf) && ("CHARACTERIZATION" >< buf))
    {
     security_warning(port:port);
     exit(0);
    }
  }
}
