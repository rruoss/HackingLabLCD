# OpenVAS Vulnerability Test
# $Id: mercuryboard_multiple_vuln.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Multiple Vulnerabilities in MercuryBoard
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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
tag_summary = "The remote host is running MercuryBoard, a message board system written
in PHP.

Multiple vulnerabilities have been discovered in the product that allow
an attacker to cause numerous cross site scripting attacks, inject
arbitrary SQL statements and disclose the path under which the product
has been installed.";

tag_solution = "Upgrade to MercuryBoard version 1.1.3.";

# Multiple vulnerabilities in MercuryBoard 1.1.1
# "Alberto Trivero" <trivero@jumpy.it>
# 2005-01-24 23:37

if(description)
{
 script_id(16247);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id(
    "CVE-2005-0306",
    "CVE-2005-0307",
    "CVE-2005-0414",
    "CVE-2005-0460",
    "CVE-2005-0462",
    "CVE-2005-0662",
    "CVE-2005-0663",
    "CVE-2005-0878"
 );
 script_bugtraq_id(12359, 12503, 12578, 12706, 12707, 12872); 
 script_xref(name:"OSVDB", value:"13262");
 script_xref(name:"OSVDB", value:"13263");
 script_xref(name:"OSVDB", value:"13264");
 script_xref(name:"OSVDB", value:"13265");
 script_xref(name:"OSVDB", value:"13266");
 script_xref(name:"OSVDB", value:"13267");
 script_xref(name:"OSVDB", value:"13764");
 script_xref(name:"OSVDB", value:"13787");
 script_xref(name:"OSVDB", value:"14307");
 script_xref(name:"OSVDB", value:"14308");


 name = "Multiple Vulnerabilities in MercuryBoard";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of an old version of mercuryBoard";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
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

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ( "Powered by <a href='http://www.mercuryboard.com' class='small'><b>MercuryBoard</b></a>" >< r )
 {
  if ( egrep(pattern:'<b>MercuryBoard</b></a> \\[v(0\\..*|1\\.0\\..*|1\\.1\\.[0-2])\\]', string:r) ) 
  {
   security_hole(port);
   exit(0);
  }
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
