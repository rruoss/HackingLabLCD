###############################################################################
# OpenVAS Vulnerability Test
# $Id: default_http_auth_credentials.nasl 13 2013-10-27 12:16:33Z jan $
#
# HTTP Brute Force Logins with default Credentials 
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "It was possible to login into the remote Web Application using default credentials.";

tag_solution = "Change the password as soon as possible.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary + "

 Solution:
 " + tag_solution;
if (description)
{

 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_tag(name:"risk_factor", value:"Critical");
 script_id(103240);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-06 14:38:09 +0200 (Tue, 06 Sep 2011)");
 script_name("HTTP Brute Force Logins with default Credentials");
 script_description(desc);
 script_summary("Checks if login with default credentials is possible");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("default_credentials.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(! url = get_kb_item(string("www/", port, "/content/auth_required")))exit(0);

foreach credential (credentials) {

  credential = str_replace(string: credential, find:"\;", replace:"#sem#");

  user_pass = split(credential, sep:";",keep:FALSE);
  if(isnull(user_pass[0]) || isnull(user_pass[1]))continue;

  user = chomp(user_pass[0]);
  pass = chomp(user_pass[1]);

  user = str_replace(string: user, find:"#sem#", replace:";");
  pass = str_replace(string: pass, find:"#sem#", replace:";");

  if(tolower(pass) == "none")pass = "";
  if(tolower(user) == "none")user = "";

  userpass = string(user,":",pass);
  userpass64 = base64(str:userpass);

  req = string("GET ", url," HTTP/1.1\r\n", "Host: ",  get_host_name(),"\r\n\r\n");
  resp = http_keepalive_send_recv(port:port, data:req);

  if(resp !~ "HTTP/1.. 401")exit(0); # just to be sure

  req = string("GET ", url," HTTP/1.1\r\n",
               "Host: ", get_host_name(),"\r\n",
               "Authorization: Basic ",userpass64,"\r\n",
               "\r\n"); 

  resp = http_keepalive_send_recv(port:port, data:req);

  if((resp =~ "HTTP/1.. 200" || resp =~ "HTTP/1.. 30") && resp !~ "HTTP/1.. 401") {

    default_credential_found = TRUE;
    report += string(url,":",user,':',pass,"\n");  

 }

}

if(default_credential_found) {

  report = string("It was possible to login with the following credentials\n\nURL:User:Password\n\n",report);
  report = string(desc,"\n",report);

  security_hole(port:port,data:report);
  exit(0);

}  
