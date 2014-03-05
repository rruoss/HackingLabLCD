# OpenVAS Vulnerability Test
# $Id: smbcl_getversion.nasl 16 2013-10-27 13:09:52Z jan $
# Description: SMB Test
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
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
tag_summary = "Test remote host SMB Functions";

# $Revision: 16 $

if(description)
{

 script_id(90011);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-05-15 23:18:24 +0200 (Thu, 15 May 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "SMB Test";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 summary = "Determines the OS and SMB Version of Host";
 script_summary(summary);
 script_dependencies("smb_authorization.nasl");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
 script_family("Windows");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The code starts here
#
include("smb_nt.inc");
include("smbcl_func.inc");

port = kb_smb_transport();
if(!port){
   port = 139;
}

if(!get_port_state(port))exit(0);

if (check_smbcl() == 0) exit(0);

report = string("OS Version = "+get_kb_item("SMB/OS")) + string("\n");
report = report + string("Domain = "+ get_kb_item("SMB/DOMAIN")) + string("\n");
report = report + string("SMB Serverversion = "+ get_kb_item("SMB/SERVER")) + string("\n");
security_note(port:0, proto:"SMBClient", data:report);

exit(0);



#=====
#This is for testing only !
#Here you can see what is possible with smbcl_func.nasl
#This example will read the Versionnumber of all exe in the Windows\ Directory
#=====

  win_dir = get_windir();
#  path = win_dir+"Microsoft.NET\Framework\v2.0.50727\";
  path = win_dir; # +"SYSTEM32\";
  filespec = "*.exe";
#  filespec = "system.WEB.dll";

  r = smbgetdir(share: "C$", dir: path+filespec, typ: 1 );
  if( !isnull(r) ) {
    foreach i (keys(r)) {
      tmp_filename = get_tmp_dir()+"tmpfile"+rand();
      orig_filename = path+r[i];
      if( smbgetfile(share: "C$", filename: orig_filename, tmp_filename: tmp_filename) ) {
        report = string("SMB File successfully loaded ") + string("\n");
        v = GetPEFileVersion(tmp_filename:tmp_filename, orig_filename:orig_filename);
        unlink(tmp_filename);
        report = report + "Fileversion : C$ "+orig_filename + " "+v+string("\n");
        report = report + "KB Fileversion "+string("Getting SMB-KB File -> ")+get_kb_item("SMB/FILEVERSION/"+orig_filename) + string("\n");
        security_note(port:0, proto:"SMBClient", data:report);    
      } else {
        report = string("Error getting SMB-File -> "+get_kb_item("SMB/ERROR")) + string("\n");
        security_note(port:0, proto:"SMBClient", data:report);
      }
    }
  } else {
    report = string("No Files found according filespec : ")+path+filespec + string("\n");
    security_note(port:0, proto:"SMBClient", data:report);
  }
exit(0);
