###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Reading Apache htaccess Files (win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Reading Apache htaccess Files

   This script get the AuthUserFile configuration of an list 
  of Apache htaccess files.";

if(description)
{
  script_id(96021);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Reading Apache htaccess Files (win)");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Reading Apache htaccess Files (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
   
  script_dependencies("secpod_reg_enum.nasl", "GSHB_WMI_Apache.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("GSHB_read_file.inc");

htaccessList = get_kb_item("WMI/Apache/htaccessList");

if ("None" >< htaccessList){
  set_kb_item(name:"GSHB/Apache/AccessPWD", value:"None");
  log_message(port:0, proto: "IT-Grundschutz", data:string("No Apache Installed") + string("\n"));
exit(0);
}


if(!get_kb_item("SMB/WindowsVersion")){
  set_kb_item(name:"GSHB/ApacheConfig", value:"error");
  set_kb_item(name:"GSHB/ApacheConfig/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

if(htaccessList){
htaccessList = split(htaccessList, sep:'|', keep:0);
for (h=0; h<max_index(htaccessList); h++)
    {
        if (htaccessList[h] >!< 'Name' || ''){

            path = htaccessList[h];
            path = split(path, sep:":", keep:0);
            file = ereg_replace(pattern:'\\\\', replace:'\\', string:path[1]);
            share = path[0] + "$";
            htaccessfile = GSHB_read_file(share: share, file: file, offset: 0);
                if (!htaccessfile){
                   log_message(port:port, data:"Cannot access/open the Apache .htaccess file.");
                } else {
                    AccessPWD = egrep(pattern:'^ *AuthUserFile *', string:htaccessfile);
                    AccessPWD = ereg_replace(pattern:'^ *AuthUserFile *|\"|\n|\r',replace:'', string:AccessPWD);
                    KB = KB + AccessPWD + "|";

                }
         }
   }
}
else KB = "None";

set_kb_item(name:"GSHB/Apache/AccessPWD", value:KB);
exit(0);

