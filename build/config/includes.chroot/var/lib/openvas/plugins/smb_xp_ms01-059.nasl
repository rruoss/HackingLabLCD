# OpenVAS Vulnerability Test
# $Id: smb_xp_ms01-059.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Unchecked Buffer in XP upnp
#
# Authors:
# Michael Scheidell <scheidell at secnap.net>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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
tag_summary = "Unchecked Buffer in Universal Plug and Play Can
Lead to System Compromise for Windows XP (Q315000)

By sending a specially-malformed NOTIFY directive,
it would be possible for an attacker to cause code
to run in the context of the UPnP service, which
runs with system privileges on Windows XP.

The UPnP implementations do not adequately
regulate how it performs this operation, and this
gives rise to two different denial-of-service
scenarios. (CVE-2001-0877)

See http://www.microsoft.com/technet/security/bulletin/ms01-059.mspx";

if(description)
{
 script_id(10835);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3723);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0876");
 name = "Unchecked Buffer in XP upnp";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Determines whether the hotfix Q315000 is installed";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
 family = "Windows : Microsoft Bulletins";
 script_family(family);
 
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q315000") > 0 )
	security_hole(get_kb_item("SMB/transport"));

