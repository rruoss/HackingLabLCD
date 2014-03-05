###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_49940.nasl 13 2013-10-27 12:16:33Z jan $
#
# Samba 'mtab' Lock File Handling Local Denial of Service Vulnerability
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
tag_summary = "Samba is prone to a local denial-of-service vulnerability that affects
the mounting utilities 'mount.cifs' and 'umount.cifs'.

A local attacker can exploit this issue to cause the mounting
utilities to abort, resulting in a denial-of-service condition.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103283);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-05 13:15:09 +0200 (Wed, 05 Oct 2011)");
 script_bugtraq_id(49940);
 script_cve_id("CVE-2011-3585");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Samba 'mtab' Lock File Handling Local Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49940");
 script_xref(name : "URL" , value : "https://bugzilla.samba.org/show_bug.cgi?id=7179");
 script_xref(name : "URL" , value : "http://git.samba.org/?p=cifs-utils.git;a=commitdiff;h=810f7e4e0f2dbcbee0294d9b371071cb08268200");
 script_xref(name : "URL" , value : "http://us1.samba.org/samba/");

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
  if(version_is_less_equal(version:version,test_version:"3.6.0")) {
    security_hole(port:port);
    exit(0);
  }  
}  

exit(0);

