###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_MDaemon_39857.nasl 14 2013-10-27 12:33:37Z jan $
#
# Alt-N MDaemon SUBSCRIBE Remote Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_summary = "MDaemon is prone to an information-disclosure vulnerability because it
fails to sufficiently sanitize user-supplied input.

Exploiting this issue may allow an attacker to gain access to
information from arbitrary files on the vulnerable server.

MDaemon 11.0.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100630);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-06 13:19:12 +0200 (Thu, 06 May 2010)");
 script_bugtraq_id(39857);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Alt-N MDaemon SUBSCRIBE Remote Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39857");
 script_xref(name : "URL" , value : "http://www.altn.com/");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2010/May/9");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if remote MDaemon version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smtp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;
if(!get_port_state(port))exit(0);

banner = get_smtp_banner(port:port);
if(!banner || "MDaemon" >!< banner)exit(0);

version = eregmatch(pattern:"MDaemon[^0-9]+([0-9.]+);", string: banner);
if(isnull(version[1]))exit(0);

if(version_is_equal(version:version[1],test_version:"11.0.1")) {
  security_warning(port:port);
  exit(0);
}  

exit(0);


  
