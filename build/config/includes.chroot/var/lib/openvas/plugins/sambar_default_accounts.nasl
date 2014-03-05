# OpenVAS Vulnerability Test
# $Id: sambar_default_accounts.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Sambar Default Accounts
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2003 Renaud Deraison
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
tag_summary = "The Sambar web server comes with some default accounts.

This script makes sure that all these accounts have a password
set.";

tag_solution = "Set a password for each account";

if(description)
{
 script_id(80081);
 script_version("$Revision: 16 $");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_name("Sambar Default Accounts");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Tests for default accounts";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))
  exit(0);

valid = NULL;

users = make_list("billy-bob", "admin", "anonymous");

foreach user (users) {
  content = string("RCpage=%2Fsysuser%2Fdocmgr%2Fbrowse.stm",
                   "&onfailure=%2Fsysuser%2Fdocmgr%2Frelogin.htm",
                   "&path=%2F&RCSsortby=name&RCSbrowse=%2Fsysuser%2Fdocmgr",
                   "&RCuser=", user, "&RCpwd=");

  req = string("POST /session/login HTTP/1.1\r\n",
               "Host: ", get_host_name(), "\r\n",
               "User-Agent: Mozilla/5.0 (OpenVAS; rv:1.2.1)\r\n",
               "Accept: text/xml, text/html\r\n",
               "Accept-Language: us\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(content), "\r\n\r\n",
               content);


  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL)
    exit(0);

  #display(res);

  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 404 ", string:res))
    exit(0);


  if("Sambar Server Document Manager" >< res) {
    valid += user + '\n';
  }
}


if (valid) {
  if ("admin" >< valid)
    alert_admin = 'Note that the privileged "admin" account is affected.\n';
  else
    alert_admin = '';

  report = string('It is possible to log in as the following passwordless',
                  'users in the remote Sambar web server :\n',
                  valid, '\n', alert_admin,
                  'An attacker may use this flaw to alter the content of this',
                  'server.\n\n',
                  'Solution: Disable these accounts');
 
  security_hole(port:port, data:report);
}

