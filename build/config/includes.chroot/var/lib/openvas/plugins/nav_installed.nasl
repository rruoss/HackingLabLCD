# OpenVAS Vulnerability Test
# $Id: nav_installed.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Norton Anti Virus Check
#
# Authors:
# This script has been rewritten by Tenable Network Security
# Original script was written by Jeff Adams <jeffadams@comcast.net>;
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2004-2005 Jeff Adams / Tenable Network Security
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
tag_summary = "This plugin checks that the remote host has Norton Antivirus installed and
properly running, and makes sure that the latest Vdefs are loaded.";

tag_solution = "Make sure NAV is installed, running and using the latest VDEFS.";

if(description)
{
 script_id(80038);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 name = "Norton Anti Virus Check";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "Checks that Norton Antivirus installed and then makes sure the latest Vdefs are loaded."; 
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2004-2005 Jeff Adams / Tenable Network Security"); 
 family = "Windows"; 
 script_family(family);
 script_dependencies("secpod_reg_enum.nasl","smb_enum_services.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
   exit(0);
}

if(get_kb_item("SMB/samba"))exit(0);

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_database_version ()
{
  local_var key, item, key_h, value, path, vers;

  key = "SOFTWARE\Symantec\SharedDefs\"; 
  item = "DEFWATCH_10"; 

  if (registry_key_exists(key:key))
  {
   value = registry_get_sz(item:item, key:key);  
   if (value)
     vers = value;
   else
   {
    item = "NAVCORP_70"; 
    value = registry_get_sz(item:item, key:key);  
    if (value)
      vers = value;
    else
    {
     item = "NAVNT_50_AP1"; 
     value = registry_get_sz(item:item, key:key);  
     if (value)
       vers = value;
     else
     {
      item = "AVDEFMGR"; 
      value = registry_get_sz(item:item, key:key);  
      if (!value)
      {
       return NULL;
      }
      else
       vers = value;
     }
    }    
   }
  }

  key = "SOFTWARE\Symantec\InstalledApps\"; 
  item = "AVENGEDEFS"; 
  if (registry_key_exists(key:key))
  {
   value = registry_get_sz(item:item, key:key);
   if (value)
     path = value;
  }

  if(!path || !vers)return NULL;

  vers = substr (vers, strlen(path) + 1 , strlen(vers)-5);
  if(vers) {
    return vers;
  } else {
    return NULL;
  }   
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
function check_product_version (reg)
{
  local_var key, item, key_h, value;

  key = reg; 
  item = "version"; 
  if (registry_key_exists(key:key))
  {
   value =  registry_get_sz(item:item, key:key);
   if (value)
     return value;
  }
  
  return NULL;
}

#-------------------------------------------------------------#
# Checks if McAfee VirusScan is installed                     #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Symantec\InstalledApps\";
item = "NAVNT";
if (registry_key_exists(key:key))
{
 value = registry_get_sz(item:"SAVCE", key:key); 
 if (!value)
 {
  value = registry_get_sz(item:item, key:key);
  if (!value) 
  {
   item = "SAVCE";
   value = registry_get_sz(item:item, key:key);
  }
 }
}
if (!value || isnull(value))
{
  exit(0);  
}

set_kb_item(name: "Antivirus/Norton/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the virus database version                           #
#-------------------------------------------------------------#

# Take the first database version key
current_database_version = check_database_version (); 
 

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

services = get_kb_item("SMB/svcs"); 

# Thanks to Jeff Adams for Symantec service.
if ( services )
{
  if (("Norton AntiVirus" >!< services) && ("Symantec AntiVirus" >!< services) && ("SymAppCore" >!< services))
    running = 0;
  else
    running = 1;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#

product_version = check_product_version (reg:"SOFTWARE\Symantec\Norton AntiVirus");
if(!product_version || isnull(product_version)) {
 exit(0);
}  

#==================================================================#
# Section 3. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has the Norton Antivirus installed. It has been
fingerprinted as :

";

report += "Norton/Symantec Antivirus " + product_version + "
DAT version : " + current_database_version + "

";

#
# Check if antivirus database is up-to-date
#

# Last Database Version
virus = "20080923";
if(current_database_version && current_database_version>0) {
  if ( int(current_database_version) < ( int(virus) - 1 ) )
  {
    report += "The remote host has an out-dated version of the Norton
  virus database. Last version is " + virus + "

  ";
    warning = 1;
  }
}

#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Norton AntiVirus is not running.

";
  warning = 1;
}

#
# Create the final report
#
if (warning)
{
  report += "As a result, the remote host might be infected by viruses received by
email or other means.";

  report = string (desc,
		"\n\nPlugin output :\n\n",
		report);

  security_hole(port:port, data:report);
}
else
{
  set_kb_item (name:"Antivirus/Norton/description", value:report);
}

