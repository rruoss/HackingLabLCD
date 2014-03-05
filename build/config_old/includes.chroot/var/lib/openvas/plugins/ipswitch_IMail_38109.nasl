###############################################################################
# OpenVAS Vulnerability Test
# $Id: ipswitch_IMail_38109.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ipswitch IMail Server Multiple Local Privilege Escalation Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Ipswitch IMail Server is prone to multiple local privilege-escalation
vulnerabilities.

Local attackers may exploit these issues to gain elevated privileges,
which may lead to a complete compromise of an affected computer.

IMail Server 11.01 is affected; other versions may also be
vulnerable.";


if (description)
{
 script_id(100490);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)");
 script_bugtraq_id(38109);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Ipswitch IMail Server Multiple Local Privilege Escalation Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38109");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2010-02/0076.html");
 script_xref(name : "URL" , value : "http://www.ipswitch.com/Products/IMail_Server/index.html");

 script_description(desc);
 script_summary("Determine if Ipswitch IMail Server version is 11.01");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp","Services/pop3","Services/imap", 25, 110, 143);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smtp_func.inc");
include("pop3_func.inc");
include("imap_func.inc");
include("version_func.inc");

function check_vuln(banner,port) {
  version = eregmatch(pattern: "IMail ([0-9.]+)", string: banner);
  if(!isnull(version[1])) {
   if(version_is_equal(version: version[1], test_version:"11.01")) {
     security_hole(port:port);
     return 0;
   }  
  }  
}  

port = get_kb_item("Services/smtp");
if(!port) port = 25;
if(banner = get_smtp_banner(port:port)) {
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }  
}

port = get_kb_item("Services/pop3");
if(!port) port = 110;
if(banner = get_pop3_banner(port:port)) {
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }
}

port = get_kb_item("Services/imap");
if(!port) port = 143;
if(banner = get_imap_banner(port:port)) {
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }  
}

exit(0);
