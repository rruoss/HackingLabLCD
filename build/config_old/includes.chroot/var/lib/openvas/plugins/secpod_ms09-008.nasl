###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-008.nasl 15 2013-10-27 12:49:54Z jan $
#
# Vulnerabilities in DNS and WINS Server Could Allow Spoofing (962238)
#
# Authors:
# Chandan S <schandan@secpod.com>
# 
#  Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-03
#       - To detect file version 'dns.exe' on win 2008 server
#
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attacker to execute specially crafted
  DNS queries to poison the DNS cache and can redirect traffic by registering
  WPAD or ISATP in the WINS database pointing to any desired IP address.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K Server Service Pack 4 and prior.
  Microsoft Windows 2003 Server Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 1 and prior.";
tag_insight = "- Error in the Windows DNS server may cause it to not properly reuse cached
    responses.
  - Error in the Windows DNS server may cause it to not properly cache
    responses to specifially crafted DNS queries.
  - Failure in access validation to restrict access when defining WPAD and
    ISATAP entries.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-008.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-008.";

if(description)
{
  script_id(900088);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-11 16:41:30 +0100 (Wed, 11 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-0233", "CVE-2009-0234", "CVE-2009-0093", "CVE-2009-0094");
  script_bugtraq_id(33982, 33988, 33989, 34013);
  script_name("Vulnerabilities in DNS and WINS Server Could Allow Spoofing (962238)");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-008.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable File Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, win2003:3, win2008:2) <= 0){
  exit(0);
}

function get_ver(exeFile)
{
  exePath = registry_get_sz(item:"Install Path",
                          key:"SOFTWARE\Microsoft\COM3\Setup");
  if(!exePath){
    return(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:exePath + exeFile);
  fileVer = GetVer(file:file, share:share);
  if(fileVer){
    return fileVer;
  }
  else return(0);
}

# Check for WINS service port status
winsPort = 42;
if(get_port_state(winsPort))
{
  if(registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\WINS"))
  {
    if(hotfix_missing(name:"961064") == 1) #Grep for WINS Hotfix 961064 (MS09-008)
    {
      fileVer = get_ver(exeFile:"\wins.exe");
      if(fileVer)
      {
        if(get_kb_item("SMB/Win2K/ServicePack")) # Win-2000 SP4 and prior
        {
          if(version_is_less(version:fileVer, test_version:"5.0.2195.7241")){
            security_hole(winsPort);
          }
        }

        SP = get_kb_item("SMB/Win2003/ServicePack");
        if("Service Pack 1" >< SP) # Win-2003 SP1
        {
          if(version_is_less(version:fileVer, test_version:"5.2.3790.3281")){
            security_hole(winsPort);
          }
        }
        else if("Service Pack 2" >< SP) # Win-2003 SP2
        {
          if(version_is_less(version:fileVer, test_version:"5.2.3790.4446")){
            security_hole(winsPort);
          }
        }
      }
    }
  }
}

#Check for DNS service port status
dnsPort = 53;
if(get_port_state(dnsPort))
{
  if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\DNS")){
    exit(0);
  }
  if(hotfix_missing(name:"961063") == 1) #Grep for DNS Hotfix 961063 (MS09-008)
  {
    fileVer = get_ver(exeFile:"\dns.exe");
    if(fileVer)
    {
      if(get_kb_item("SMB/Win2K/ServicePack")) # Win-2000 SP4 and prior
      {
        if(version_is_less(version:fileVer, test_version:"5.0.2195.7260")){
          security_hole(dnsPort);
        }
        exit(0);
      }

      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP) # Win-2003 SP1
      {
        if(version_is_less(version:fileVer, test_version:"5.2.3790.3295")){
          security_hole(dnsPort);
        }
        exit(0);
      }
      else if("Service Pack 2" >< SP) # Win-2003 SP2
      {
        if(version_is_less(version:fileVer, test_version:"5.2.3790.4460")){
          security_hole(dnsPort);
        }
        exit(0);
      }
    }
    
    ## Get dns.exe path for 2008 server  
    sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
    if(!sysPath){
     exit(0);
    }

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
    file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\System32\dns.exe");

    exeVer = GetVer(file:file, share:share);
    if(exeVer)
    {
      SP = get_kb_item("SMB/Win2008/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for dns.exe version < 6.0.6001.18214
        if(version_is_less(version:exeVer, test_version:"6.0.6001.18214")){
          security_hole(0);
        }
        exit(0);
      }
    } 
  }   
}
 
