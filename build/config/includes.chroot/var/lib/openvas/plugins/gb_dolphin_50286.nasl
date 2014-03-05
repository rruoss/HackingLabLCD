###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolphin_50286.nasl 13 2013-10-27 12:16:33Z jan $
#
# Boonex Dolphin 'xml/get_list.php' SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "Boonex Dolphin is prone to an SQL-injection vulnerability because the
application fails to properly sanitize user-supplied input before
using it in an SQL query.

A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit vulnerabilities in the
underlying database.

Boonex Dolphin 6.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103306);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)");
 script_bugtraq_id(50286);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Boonex Dolphin 'xml/get_list.php' SQL Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50286");
 script_xref(name : "URL" , value : "http://www.boonex.com/dolphin/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520146");
 script_xref(name : "URL" , value : "http://en.securitylab.ru/lab/PT-2011-14");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Boonex Dolphin is prone to an SQL-injection vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/dolphin",cgi_dirs());

foreach dir (dirs) {
   
  url =  string(dir,"/xml/get_list.php?dataType=ApplyChanges&iNumb=1&iIDcat=%27"); 

  if(http_vuln_check(port:port, url:url,pattern:"You have an error in your SQL syntax")) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);
