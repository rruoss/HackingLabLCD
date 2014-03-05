# OpenVAS Vulnerability Test
# $Id: webcalendar_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WebCalendar SQL Injection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "The remote installation of WebCalendar may allow an attacker to cause
an SQL Injection vulnerability in the program allowing an attacker to
cause the program to execute arbitrary SQL statements.";

if(description)
{
 script_id(15752);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id(
   "CVE-2004-1506",
   "CVE-2004-1507",
   "CVE-2004-1508",
   "CVE-2004-1509",
   "CVE-2004-1510"
 );
 script_bugtraq_id(11651);
 
 name = "WebCalendar SQL Injection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for the presence of an SQL injection in view_topic.php";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("webcalendar_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("webcalendar/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 req = http_get(item:string(loc, "/view_entry.php?id=1'&date=1"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if(egrep(pattern:"You have an error in your SQL syntax", string:r) ||
    egrep(pattern:"SELECT webcal_entry.cal_id FROM webcal_entry", string: r)
   )
 {
 	security_hole(port);
	exit(0);
 }
}
