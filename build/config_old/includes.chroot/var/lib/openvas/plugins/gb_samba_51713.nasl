###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_51713.nasl 12 2013-10-27 11:15:33Z jan $
#
# Samba Memory Leak Local Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "Samba is prone to a local denial-of-service vulnerability.

A local attacker can exploit this issue to exhaust available memory,
denying access to legitimate users.

The vulnerability affects Samba versions 3.6.0 through 3.6.2.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(103411);
 script_bugtraq_id(51713);
 script_cve_id("CVE-2012-0817");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version ("$Revision: 12 $");

 script_name("Samba Memory Leak Local Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51713");
 script_xref(name : "URL" , value : "http://www.samba.org/samba/security/CVE-2012-0817");
 script_xref(name : "URL" , value : "http://www.samba.org");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-09 10:12:15 +0100 (Thu, 09 Feb 2012)");
 script_description(desc);
 script_summary("Determine if installed Samba version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139,445);
 script_require_keys("SMB/NativeLanManager");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_kb_item("SMB/transport");
if(!port)port = 139;

if(!get_port_state(port))exit(0);

if(version = get_samba_version()) {
  if(version_in_range(version:version,test_version:"3.6",test_version2:"3.6.2")) {
    security_warning(port:port);
    exit(0);
  }  
}  

exit(0);
