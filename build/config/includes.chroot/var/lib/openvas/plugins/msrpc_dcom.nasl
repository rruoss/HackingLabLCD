# OpenVAS Vulnerability Test
# $Id: msrpc_dcom.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Microsoft RPC Interface Buffer Overrun (823980)
#
# Authors:
# KK Liu
#
# Copyright:
# Copyright (C) 2003 KK LIU
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
tag_summary = "The remote host is running a version of Windows which has a flaw in
 its RPC interface which may allow an attacker to execute arbitrary code
 and gain SYSTEM privileges.  There is at least one Worm which is
 currently exploiting this vulnerability.  Namely, the MsBlaster worm.";

tag_solution = "see
 http://www.microsoft.com/technet/security/bulletin/MS03-026.mspx
 http://www.microsoft.com/technet/security/bulletin/MS04-012.mspx
 http://www.microsoft.com/technet/security/bulletin/MS05-012.mspx
 http://www.microsoft.com/technet/security/bulletin/MS05-051.mspx
 http://www.microsoft.com/technet/security/bulletin/MS06-018.mspx";

# [LSD] Critical security vulnerability in Microsoft Operating Systems
# Check methods based on Eeye's MSRPC scanner 1.03
#
# Updated 7/29/2003 - Now works for NT4
# Updated 8/13/2003 - Now works for Win 95/98/ME

if(description)
{
 script_id(11808);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8205);
 script_cve_id("CVE-2003-0352");
 script_xref(name:"IAVA", value:"2003-A-0011");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "Microsoft RPC Interface Buffer Overrun (823980)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "[LSD] Critical security vulnerability in Microsoft Operating Systems";
 script_summary(summary);

 script_category(ACT_ATTACK);

 script_copyright("This script is Copyright (C) 2003 KK LIU");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_ports("Services/msrpc", 135, 593);
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


#
# The script code starts here
#

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

#if(!get_kb_item("Launched/11835"))exit(0);
#if(get_kb_item("SMB/KB824146"))exit(0);
#if(get_kb_item("SMB/KB824146_cant_be_verified"))exit(0);

if(hotfix_check_sp(xp:3, win2k:5, win2003:2) <= 0){
  exit(0);
}

# Check for update rollup
rollUp = registry_key_exists(key:"SOFTWARE\Microsoft\Updates\Windows 2000\SP5\Update Rollup 1");
if(rollUp){
  exit(0);
}

# Supersede checks (MS04-012, MS05-012, MS05-051 and MS06-018)
if(hotfix_missing(name:"828741") == 0 || hotfix_missing(name:"873333") == 0 ||
   hotfix_missing(name:"902400") == 0 || hotfix_missing(name:"913580") == 0){
  exit(0);
}

# Check for Hotfix 823980 (MS03-026)
if(hotfix_missing(name:"823980") == 1){
  security_hole(get_kb_item("SMB/transport"));
}
