###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_43212.nasl 14 2013-10-27 12:33:37Z jan $
#
# Samba SID Parsing Remote Buffer Overflow Vulnerability
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
tag_summary = "Samba is prone to a remote stack-based buffer-overflow vulnerability
because it fails to properly bounds-check user-supplied data before
copying it to an insufficiently sized memory buffer.

An attacker can exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts will
likely result in a denial of service.

Samba versions prior to 3.5.5 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100803);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-15 16:23:15 +0200 (Wed, 15 Sep 2010)");
 script_bugtraq_id(43212);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3069");

 script_name("Samba SID Parsing Remote Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43212");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/history/samba-3.5.5.html");
 script_xref(name : "URL" , value : "http://www.samba.org");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/security/CVE-2010-2069.html");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Samba version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139, 445);
 script_require_keys("SMB/NativeLanManager");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

if(!get_port_state(port))exit(0);


if(version = get_samba_version()) {
  if(version_is_less(version:version,test_version:"3.5.5")) {
    security_hole(port:port);
    exit(0);
  }  
}  

exit(0);
