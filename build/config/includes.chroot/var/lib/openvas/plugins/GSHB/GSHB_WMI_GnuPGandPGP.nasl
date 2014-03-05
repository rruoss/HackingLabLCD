###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Get GnuPG and PGP Version and User they have an pubring (win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# Set in an Workgroup Environment under Vista with enabled UAC this DWORD to access WMI:
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy to 1
#
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
tag_summary = "Get GnuPG and PGP Version and User they have an pubring (win)";

if(description)
{
  script_id(96045);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get GnuPG and PGP Version and User they have an pubring (win)");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Get GnuPG and PGP Version and User they have an pubring (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_mandatory_keys("Tools/Present/wmi");
   
#  script_require_ports(139, 445);
  script_dependencies("secpod_reg_enum.nasl", "GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

host    = get_host_ip();
usrname = get_kb_item("SMB/login");
domain  = get_kb_item("SMB/domain");
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd  = get_kb_item("SMB/password");
OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/GnuPGVersion", value:"error");
  set_kb_item(name:"WMI/PGPVersion", value:"error");
  set_kb_item(name:"WMI/GnuPGpubringsUser", value:"error");
  set_kb_item(name:"WMI/PGPpubringsUser", value:"error");
  set_kb_item(name:"WMI/PGP/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);


if(!handle || !handlereg){
  set_kb_item(name:"WMI/GnuPGVersion", value:"error");
  set_kb_item(name:"WMI/PGPVersion", value:"error");
  set_kb_item(name:"WMI/GnuPGpubringsUser", value:"error");
  set_kb_item(name:"WMI/PGPpubringsUser", value:"error");
  set_kb_item(name:"WMI/PGP/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

GNUPGKEY = wmi_reg_enum_value(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG");

if (GNUPGKEY)
{
  query1 = 'select Name, FileSize from CIM_DataFile WHERE FileName = "pubring" AND Extension LIKE "gpg"';
  gnupgvers = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG", key_name:"DisplayVersion");
  gnupgpubrings = wmi_query(wmi_handle:handle, query:query1);
  if (gnupgpubrings)
  {
    gnupgpubrings = split(gnupgpubrings, sep:'\n', keep:0);
    for(g=1; g<max_index(gnupgpubrings); g++)
    {
       if("FileSize|Name" >< gnupgpubrings[g]){
         continue;
       }
       path = split(gnupgpubrings[g], sep:"|", keep:0);
       if(path !=NULL)
       {
       if(path[0] > 0) 
       {
         name = split(path[1], sep:"\", keep:0);
         if(OSVER >= 6)
         {
           b = max_index(name) -5 ;
         }
         else
         {
           b = max_index(name) -4 ;
         }
         gnupgpubringsuser = gnupgpubringsuser + "Username: " + name[b] + ", Pubringgr��e: " + path[0] + " Byte ;";
       }
       }
    } 
  }
  else
  {
    gnupgpubringsuser = "none";
  }
}else
{
gnupgvers = "none";
gnupgpubringsuser = "none";
}

query2 = 'select Version from CIM_DataFile WHERE FileName = "pgpdesk" AND Extension LIKE "exe"';
pgpversion =  wmi_query(wmi_handle:handle, query:query2);

if (pgpversion)
{
  pgpversion = split(pgpversion, sep:"|", keep:0);
  pgpversion = ereg_replace(pattern:'\n', string:pgpversion[2], replace:''); 
  query3 = 'select Name, FileSize from CIM_DataFile WHERE FileName = "pubring" AND Extension LIKE "pkr"';
  pgppubrings = wmi_query(wmi_handle:handle, query:query3);
  
  if (pgppubrings)
  {
    pgppubrings = split(pgppubrings, sep:'\n', keep:0);
    for(i=1; i<max_index(pgppubrings); i++)
    {
       if("FileSize|Name" >< pgppubrings[i]){
         continue;
       }
       path = split(pgppubrings[i], sep:"|", keep:0);
       if(path !=NULL)
       { 
       if(path[0] > 0) 
       {
         name = split(path[1], sep:"\", keep:0);
                  if(OSVER >= 6)
         {
           a = max_index(name) -5 ;
         }
         else
         {
           a = max_index(name) -4 ;
         }
         pgppubringsuser = pgppubringsuser + "Username: " + name[a] + ", Pubringgr��e: " + path[0] + " Byte ;";
       }

       }
    } 
  }
  else
  {
    pgppubringsuser = "none";
  }
}else 
{
  pgppubringsuser = "none";
  pgpversion = "none";
}

if(!pgppubringsuser) pgppubringsuser = "none";
if(!gnupgpubringsuser) gnupgpubringsuser = "none";

set_kb_item(name:"WMI/GnuPGVersion", value:gnupgvers);
set_kb_item(name:"WMI/PGPVersion", value:pgpversion);
set_kb_item(name:"WMI/GnuPGpubringsUser", value:gnupgpubringsuser);
set_kb_item(name:"WMI/PGPpubringsUser", value:pgppubringsuser);

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
