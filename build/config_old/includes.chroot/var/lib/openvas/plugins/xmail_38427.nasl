###############################################################################
# OpenVAS Vulnerability Test
# $Id: xmail_38427.nasl 14 2013-10-27 12:33:37Z jan $
#
# XMail Insecure Temporary File Creation Vulnerability
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
tag_summary = "XMail creates temporary files in an insecure manner.

An attacker with local access could potentially exploit this issue to
perform symbolic-link attacks, overwriting arbitrary files in the
context of the affected application.

Successfully mounting a symlink attack may allow the attacker to
delete or corrupt sensitive files, which may result in a denial of
service. Other attacks may also be possible.

Versions prior to XMail 1.27 are affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100512);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-02 12:58:40 +0100 (Tue, 02 Mar 2010)");
 script_bugtraq_id(38427);
 script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("XMail Insecure Temporary File Creation Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38427");
 script_xref(name : "URL" , value : "http://www.xmailserver.org/ChangeLog.html#feb_25__2010_v_1_27");
 script_xref(name : "URL" , value : "http://www.xmailserver.org/");

 script_description(desc);
 script_summary("Determine if XMail version is < 1.27");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/smtp", 25);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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
if(!banner)exit(0);
banner = tolower(banner);

if("xmail" >!< banner)exit(0);

version = eregmatch(pattern: "xmail ([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

if(version_is_less(version: version[1], test_version: "1.27")) {
  security_warning(port:port);
  exit(0);
}   

exit(0);

  
