# OpenVAS Vulnerability Test
# $Id: js.scob.trojan.nasl 17 2013-10-27 14:01:43Z jan $
# Description: JS.Scob.Trojan or Download.Ject Trojan
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
tag_summary = "JS.Scob.Trojan or Download.Ject Trojan

JS.Scob.Trojan or Download.Ject is a simple Trojan that executes a 
JavaScript file from a remote server. 

The Trojan's dropper sets it as the document footer for all pages 
served by IIS Web sites on the infected computer.  The presence of 
Kk32.dll or Surf.dat may indicate a client side infection.  More 
information is available here:

http://www.microsoft.com/security/incident/download_ject.mspx";

tag_solution = "Use Latest Anti Virus to clean machine. Virus Definitions
and removal tools are being released as of 06/25/04";

if(description)
{
 script_id(12286);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 name = "JS.Scob.Trojan or Download.Ject Trojan";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "JS.Scob.Trojan/JS/Exploit-DialogArg.b Trojan";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Jeff Adams");
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
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
   exit(0);
}

rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"SystemRoot");

if (! rootfile)
	exit(0);

files[0] = string(rootfile, "\\system32\\kk32.dll");
files[1] = string(rootfile, "\\system32\\Surf.dat");


foreach file (files) 
{
        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:file);
        file  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:file);
        myread = read_file(file:file, share:share, offset:0,count:4);
        if (myread) {
         security_hole(port);
         exit(0);
	} 
}

exit(0);




