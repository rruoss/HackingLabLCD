# OpenVAS Vulnerability Test
# $Id: samba_arbitrary_file_access.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Samba Remote Arbitrary File Access
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
tag_summary = "The remote Samba server, according to its version number, is vulnerable 
to a remote file access vulnerability.  


This vulnerability allows an attacker to access arbitrary files which exist
outside of the shares's defined path.

An attacker needs a valid account to exploit this flaw.";

tag_solution = "Upgrade to Samba 2.2.11 or 3.0.7";

#  Ref: Karol Wiesek - iDEFENSE 

if(description)
{
 script_id(15394);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(11216, 11281);
 script_cve_id("CVE-2004-0815");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Samba Remote Arbitrary File Access";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "checks samba version";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Remote file access";
 script_family(family);
 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.2\.([0-9]|10)[^0-9]*$",string:lanman))
   security_hole(139);
	 
 if(ereg(pattern:"Samba 3\.0\.[0-5]$", string:lanman))
   security_hole(139);
}
