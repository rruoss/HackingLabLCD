# OpenVAS Vulnerability Test
# $Id: oracle9i_isqlplus_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle 9iAS iSQLplus XSS
#
# Authors:
# Frank Berger <dev.null@fm-berger.de>
# <http://www.fm-berger.de>
#
# Copyright:
# Copyright (C) 2004 Frank Berger
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
tag_summary = "The login-page of Oracle9i iSQLplus allows the injection of HTML and Javascript
code via the username and password parameters.


Description :


The remote host is running a version of the Oracle9i 'isqlplus' CGI which
is vulnerable to a cross site scripting issue.

An attacker may exploit this flaw to to steal the cookies of legitimate 
users on the remote host.";

# This vulnerability was found by 
# Rafel Ivgi, The-Insider <theinsider@012.net.il>

if(description)
{
 script_id(12112);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"3.0");
 script_tag(name:"cvss_base_vector", value:"AV:R/AC:H/Au:N/C:P/A:N/I:N/B:C");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Oracle 9iAS iSQLplus XSS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Test for the possibility of an Cross-Site-Scripting XSS Attack in Oracle9i iSQLplus";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Frank Berger");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 script_xref(name : "URL" , value : "http://www.securitytracker.com/alerts/2004/Jan/1008838.html");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(get_port_state(port))
{ 
 req = http_get(item:"/isqlplus?action=logon&username=foo%22<script>foo</script>&password=test", port:port);	      
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);
 if( '<script>foo</script>' >< res )	
 	security_warning(port);
}
