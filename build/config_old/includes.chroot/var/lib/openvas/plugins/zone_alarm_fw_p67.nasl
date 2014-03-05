# OpenVAS Vulnerability Test
# $Id: zone_alarm_fw_p67.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ZoneAlarm Personal Firewall port 67 flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "ZoneAlarm firewall runs on this host.

This version contains a flaw that may allow a remote attacker to bypass 
the ruleset. 
The issue is due to ZoneAlarm not monitoring and alerting UDP traffic with a 
source port of 67. 

This allows an attacker to bypass the firewall to reach protected hosts without 
setting off warnings on the firewall.";

tag_solution = "Upgrade at least to version 2.1.25";

#  Ref: Wally Whacker <whacker@hackerwhacker.com>

if(description)
{
 script_id(14660);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1137);
 script_cve_id("CVE-2000-0339");  
 script_xref(name:"OSVDB", value:"1294");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "ZoneAlarm Personal Firewall port 67 flaw";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Check ZoneAlarm version";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Firewalls";
 script_family(family);
 
 script_dependencies("netbios_name_get.nasl","zone_alarm_local_dos.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport", "zonealarm/version");

 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

zaversion = get_kb_item ("zonealarm/version");
if (!zaversion) exit (0);

if(ereg(pattern:"[0-1]\.|2\.0|2\.1\.([0-9]|1[0-9]|2[0-4])[^0-9]", string:zaversion))
{
 security_hole(0);
}
