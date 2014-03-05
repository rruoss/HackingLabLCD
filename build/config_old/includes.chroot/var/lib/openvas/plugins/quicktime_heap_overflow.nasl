# OpenVAS Vulnerability Test
# $Id: quicktime_heap_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Quicktime player/plug-in Heap overflow
#
# Authors:
# Jeff Adams <jadams@netcentrics.com>
#
# Copyright:
# Copyright (C) 2004 Jeff Adams
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
tag_summary = "The remote host is using QuickTime, a popular media player/Plug-in
which handles many Media files.

This version has a Heap overflow which may allow an attacker
to execute arbitrary code on this host, with the rights of the user
running QuickTime.

More Info: http://eeye.com/html/Research/Advisories/AD20040502.html";

tag_solution = "Uninstall this software or upgrade to version 6.5.1 or higher.";

if(description)
{
 script_id(12226);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10257);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2004-0431");
 
 name = "Quicktime player/plug-in Heap overflow";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Determines the version of QuickTime Player/Plug-in";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Jeff Adams");
 family = "Windows";
 script_family(family);
 
 script_dependencies("secpod_reg_enum.nasl");
		   
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Apple Computer, Inc./Quicktime/Version");
if ( version && version < 0x06100000 ) security_hole(port);
