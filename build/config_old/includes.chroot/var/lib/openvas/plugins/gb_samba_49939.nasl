###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_49939.nasl 13 2013-10-27 12:16:33Z jan $
#
# Samba 'etc/mtab' File Appending Local Denial of Service Vulnerability
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
tag_summary = "Samba is prone to a local denial-of-service vulnerability.

A local attacker can exploit this issue to cause the computer to stop
responding, denying service to legitimate users.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103298);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-13 13:40:58 +0200 (Thu, 13 Oct 2011)");
 script_bugtraq_id(49939);
 script_cve_id("CVE-2011-1678");
 script_tag(name:"cvss_base", value:"3.3");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");

 script_name("Samba 'etc/mtab' File Appending Local Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49939");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-1678");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Samba version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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
  if(version_is_less_equal(version:version,test_version:"3.5.8")) {
    security_warning(port:port);
    exit(0);
  }  
}  

exit(0);

