# OpenVAS Vulnerability Test
# $Id: reviewpost_sql.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SQL injection in ReviewPost PHP Pro
#
# Authors:
# Astharot <astharot@zone-h.org>
#
# Copyright:
# Copyright (C) 2004 Astharot
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
tag_summary = "The remote host could be vulnerable to SQL Injection, because
you are probably running ReviewPost PHP Pro, a web-based software
that manage users opinions.

There is a flaw in this software which may allow a malicious
attacker to inject arbitrary SQL queries which allows it to
fetch data from the database.";

tag_solution = "Download the vendor supplied patch at
http://www.photopost.com/members/forum/showthread.php?s=&threadid=98098";

# Reference: http://www.zone-h.org/advisories/read/id=3864

if(description)
{
 script_id(12042);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2175");
 script_bugtraq_id(9574, 12159);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "SQL injection in ReviewPost PHP Pro"; 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "SQL Injection";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Astharot");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
 req = http_get(item:dir + "/showproduct.php?product=1'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 
 
if ("id,user,userid,cat,date,title,description,manu,keywords,bigimage,bigimage2,bigimage3,views,approved,rating" >< res ) {
	security_hole(port);
	exit(0);
	}

 req = http_get(item:dir + "/showcat.php?cat=1'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if ("id,catname FROM rp_categories" >< res ) {
	security_hole(port);
	exit(0);
	}
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (cgi_dirs()) 
 {
  check(dir:dir);
 }