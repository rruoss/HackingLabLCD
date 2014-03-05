# OpenVAS Vulnerability Test
# $Id: icq_installed.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ICQ is installed
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) ) 2003 Xue Yong Zhi
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
tag_summary = "The remote host is using ICQ - a p2p software, 
which may not be suitable for a business environment.";

tag_solution = "Uninstall this software";

if(description)
{
 script_id(11425);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 18:10:09 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(1307, 132, 246, 2664, 3226, 3813, 929);

#TODO: too long bugtraq id
 script_cve_id("CVE-1999-1418", "CVE-1999-1440", "CVE-2000-0046", "CVE-2000-0564", "CVE-2000-0552", "CVE-2001-0367", "CVE-2002-0028", "CVE-2001-1305");
 
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "ICQ is installed";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Determines if ICQ is installed";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 family = "Peer-To-Peer File Sharing";
 script_family(family);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
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


rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ICQ", item:"DisplayName");
if(rootfile)
{
 security_hole(get_kb_item("SMB/transport"));
 exit(0); 
}

rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ICQLite", item:"DisplayName");
if(rootfile)
{
 security_hole(get_kb_item("SMB/transport"));
 exit(0); 
}


