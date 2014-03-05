# OpenVAS Vulnerability Test
# $Id: gator.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Gator/GAIN Spyware Installed
#
# Authors:
# Jeff Adams <jeffrey.adams@hqda.army.mil>
#
# Copyright:
# Copyright (C) 2003 Jeff Adams
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
tag_summary = "The remote host has Gator/GAIN Spyware Installed. Gator tracks the sites that 
users visit and forwards that data back to the company's servers. Gator sells 
the use of this information to advertisers. It also lets companies launch a 
pop-up ad when users visit various Web sites. This software is not suitable 
for a business environment.";

tag_solution = "Uninstall the software";

if(description)
{
 script_id(11883);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Gator/GAIN Spyware Installed";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Determines if Gator Spyware is installed";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Jeff Adams");
 family = "Windows";
 script_family(family);
 
 script_dependencies("netbios_name_get.nasl",
 		    "smb_login.nasl","smb_registry_access.nasl",
		    "smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smb_nt.inc");

rootfile = registry_get_sz(key:"SOFTWARE\Gator.com\Gator\dyn", item:"AppExe");
if(rootfile)
{
 security_note(get_kb_item("SMB/transport"));
}
