###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tomcat_default_credentials.nasl 12 2013-10-27 11:15:33Z jan $
#
# Tomcat Manager Unauthorized Access Vulnerability
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
tag_summary = "Tomcat Manager is prone to a remote unauthorized-access
vulnerability.

An attacker can exploit this issue to upload and execute arbitrary
code, which will facilitate a complete compromise of the affected computer.";

tag_solution = "Change or remove the user from tomcat-users.xml";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103550";
CPE = "cpe:/a:apache:tomcat";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Tomcat Manager Remote Unauthorized Access Vulnerability");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-22 17:19:15 +0200 (Wed, 22 Aug 2012)");
 script_description(desc);
 script_summary("Determine if unauthorized access to the tomcat manager is possible");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_apache_tomcat_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("ApacheTomcat/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

url = '/manager/html';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 401")exit(0);

credentials = make_list("tomcat:tomcat","tomcat:none","ADMIN:ADMIN","admin:admin","manager:manager","admin:password","ovwebusr:OvW*busr1","j2deployer:j2deployer");

foreach credential (credentials) {

   user_pass = split(credential, sep:":",keep:FALSE);

   user = chomp(user_pass[0]);
   pass = chomp(user_pass[1]);

   if(tolower(pass) == "none")pass = "";

   userpass = string(user,":",pass);
   userpass64 = base64(str:userpass);

   req = string("GET ", url," HTTP/1.1\r\n",
                "Host: ", get_host_name(),"\r\n",
                "Authorization: Basic ",userpass64,"\r\n",
                "\r\n");

  resp = http_keepalive_send_recv(port:port, data:req);

  if(resp =~ "HTTP/1.. 200 OK" && "Tomcat Web Application Manager" >< resp) {

    desc = desc + '\n\nIt was possible to login into the tomcat manager using user "' + user + '" with password "' + pass + '"\n\n';

    security_hole(port:port,data:desc);
    exit(0);
  }


}  
