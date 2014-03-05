# OpenVAS Vulnerability Test
# $Id: smb_mssql7.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SMB Registry : SQL7 Patches
#
# Authors:
# Intranode <plugin@intranode.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2001 Intranode <plugin@intranode.com>
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
tag_summary = "The remote SQL server seems to be vulnerable to the
SQL abuse vulnerability described in technet article
Q256052. This problem allows an attacker who has to ability
to execute SQL queries on this host to gain elevated privileges.";

tag_solution = "http://support.microsoft.com/default.aspx?scid=kb;en-us;256052
Reference : http://online.securityfocus.com/archive/1/285915
Reference : http://online.securityfocus.com/advisories/4308";

# Should also cover BID:4135/CVE-2002-0056

if(description)
{
 script_id(10642);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5205);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-0642");
 script_xref(name:"IAVA", value:"2002-B-0004");
 name = "SMB Registry : SQL7 Patches";
 
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Determines if a key exists and is set";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2001 Intranode <plugin@intranode.com>");
 family = "Windows";

 script_family(family);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;



#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#





function check_key(key)
{
 item = "AllowInProcess";
 value = registry_get_dword(key:key, item:item);
 if(value != NULL && strlen(value) == 4) 
 {
   item = "DisallowAdHocAccess";
   value = registry_get_dword(key:key, item:item);
   if((strlen(value)) == 0)
   {
     return(1);
   }
   else if(ord(value[0]) == 0)return(1);
 }
 return(0);
}


a = check_key(key:"SOFTWARE\Microsoft\MSSQLServer\Providers\MSDAORA");
if(a){security_hole(port);exit(0);}
b = check_key(key:"SOFTWARE\Microsoft\MSSQLServer\Providers\MSDASQL");
if(b){security_hole(port);exit(0);}
c = check_key(key:"SOFTWARE\Microsoft\MSSQLServerProviders\SQLOLEDB");
if(c){security_hole(port);exit(0);}
d = check_key(key:"SOFTWARE\Microsoft\MSSQLServerProviders\Microsoft.Jet.OLEDB.4.0");
if(d){security_hole(port);exit(0);}
