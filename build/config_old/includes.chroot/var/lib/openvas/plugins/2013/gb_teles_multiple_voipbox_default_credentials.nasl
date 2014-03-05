###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teles_multiple_voipbox_default_credentials.nasl 11 2013-10-27 10:12:02Z jan $
#
# Teles VoIP Devices Default Password
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

tag_summary = "The remote Teles VoIP device is prone to a default account
authentication bypass vulnerability";

tag_insight = 'It was possible to login with username "teles-admin" and password "tcs-admin".';

tag_impact = 'This issue may be exploited by a remote attacker to gain access to
sensitive information or modify system configuration without requiring authentication.';

tag_solution = "Change the password.";
tag_vuldetect = 'This check tries to login into the remote Teles device.';

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103819";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/AU:N/C:C/I:C/A:C");

 script_name("Teles VoIP Devices Default Password");

  desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Solution:
" + tag_solution;

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-24 10:01:48 +0100 (Thu, 24 Oct 2013)");
 script_description(desc);
 script_summary("Determine if the remote Teles device has a default password");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "impact" , value : tag_impact);
   script_tag(name : "vuldetect" , value : tag_vuldetect);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }

 exit(0);

}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("Server: TELES AG" >!< banner)exit(0);

host = get_host_name();
urls = make_list("/index_vboxgsm.cgi","/index_abox.cgi","/index_vbox.cgi","/index_igate.cgi");

foreach url (urls) {

  url = '/cgi/' + url;
  req = 'GET ' + url + ' HTTP/1.1\r\nHost: ' + host + '\r\n';
  buf = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

  if(buf !~ "HTTP/1.. 401")continue;

  userpass = 'teles-admin:tcs-admin';
  userpass64 = base64(str:userpass);

  req += 'Authorization: Basic ' + userpass64 + '\r\n\r\n';
  buf = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);

  if(buf =~ "HTTP/1.. 200") {
    security_hole(port:port);
    exit(0);
  }  

}  

exit(99);
