###############################################################################
# OpenVAS Vulnerability Test
# $Id: ability_mail_server_imap_36519.nasl 15 2013-10-27 12:49:54Z jan $
#
# Code-Crafters Ability Mail Server IMAP FETCH Request Remote Denial Of Service Vulnerability
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
tag_summary = "Ability Mail Server is prone to a denial-of-service vulnerability
because it fails to adequately handle IMAP requests.

Attackers can exploit this issue to cause the affected application to
crash, denying service to legitimate users.

Versions prior to Ability Mail Server 2.70 are affected.";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100298);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-10 11:30:08 +0200 (Sat, 10 Oct 2009)");
 script_bugtraq_id(36519);
 script_cve_id("CVE-2009-3445");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Code-Crafters Ability Mail Server IMAP FETCH Request Remote Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36519");
 script_xref(name : "URL" , value : "http://www.code-crafters.com/abilitymailserver/index.html");
 script_xref(name : "URL" , value : "http://www.code-crafters.com/abilitymailserver/updatelog.html");

 script_description(desc);
 script_summary("Determine if Ability Mail Server version is < 2.70");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/imap", 143);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("smtp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/imap");
if(!port) port = 143;
if(!get_port_state(port))exit(0);

if(!banner = get_smtp_banner(port))exit(0);
if("Code-Crafters" >!< banner)exit(0);

version = eregmatch(pattern:"Ability Mail Server ([0-9.]+)", string:banner);
if(isnull(version[1]))exit(0);

if(version_is_less(version: version[1], test_version:"2.70")) {
   security_warning(port:port);
   exit(0);
  }

exit(0);

  
