# OpenVAS Vulnerability Test
# $Id: sophos_installed.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sophos Anti Virus Check
#
# Authors:
# Jason Haar <Jason.Haar@trimble.co.nz>
#
# Copyright:
# Copyright (C) 2004 Jason Haar
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
tag_summary = "This plugin checks that the remote host has the Sophos Antivirus installed 
and that it is running.";

tag_solution = "Make sure Sophos is installed and using the latest VDEFS.";

if(description)
{
 script_id(12215);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "Sophos Anti Virus Check";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "Checks that the remote host has Sophos Antivirus installed and then makes sure the latest Vdefs are loaded."; 
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2004 Jason Haar"); 
 family = "Windows"; 
 script_family(family);
 script_dependencies("secpod_reg_enum.nasl", "smb_enum_services.nasl"); 
 script_require_keys("SMB/Registry/Enumerated", "SMB/svcs");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}



services = get_kb_item("SMB/svcs");
if ( ! services ) exit(0);

version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Sophos/SweepNT/Version");
if ( ! version ) exit(0);

#
# Checks to see if the service is running 
#
if("[SWEEPSRV]" >!< services) {
	report = "
The remote host has the Sophos antivirus installed, but it
is not running.

As a result, the remote host might be infected by viruses received by
email or other means. 

Solution: Enable the remote AntiVirus and configure it to check for updates regularly.";
	security_hole(port:port, data:report);
	}
