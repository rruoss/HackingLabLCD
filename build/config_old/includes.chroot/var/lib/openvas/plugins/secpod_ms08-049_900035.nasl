##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-049_900035.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Vulnerabilities in Event System Could Allow Remote Code Execution (950974)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

include("revisions-lib.inc");
tag_impact = "Remote exploitation allows attackers to execute arbitrary code
        with system privileges.
 Impact Level : System";

tag_solution = "Run Windows Update and update the listed hotfixes or download and
 update mentioned hotfixes in the advisory from the below link.
 http://www.microsoft.com/technet/security/bulletin/ms08-049.mspx";

tag_affected = "Microsoft Windows 2K/XP/2003";

tag_insight = "Issues are due to the Microsoft Windows Event System does not properly
        validate the range of indexes when calling an array of function pointers
        and fails to handle per-user subscription requests.";


tag_summary = "This host is missing a critical security update according to
 Microsoft Bulletin MS08-049.";

if(description)
{
 script_id(900035);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
 script_bugtraq_id(30584);
 script_cve_id("CVE-2008-1456", "CVE-2008-1457");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_category(ACT_GATHER_INFO);
 script_family("Windows : Microsoft Bulletins");
 script_name("Vulnerabilities in Event System Could Allow Remote Code Execution (950974)");
 script_summary("Check for the vulnerable File Version");
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
 " + tag_solution; script_description(desc);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-049.mspx");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("smb_nt.inc");
 include("secpod_reg.inc");
 include("version_func.inc");
 include("secpod_smb_func.inc");

 if(hotfix_check_sp(xp:3, win2k:5, win2003:3, winVista:2, win2008:2) <= 0){
	 exit(0);
 }

 if(hotfix_missing(name:"950974") == 0){
                exit(0);
 }

 function get_version()
 {

        dllPath = registry_get_sz(item:"Install Path",
                  key:"SOFTWARE\Microsoft\COM3\Setup");

        dllPath += "\Es.dll";
        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
        file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

        name    =  kb_smb_name();
        login   =  kb_smb_login();
        pass    =  kb_smb_password();
        domain  =  kb_smb_domain();
        port    =  kb_smb_transport();

        soc = open_sock_tcp(port);
        if(!soc){
                exit(0);
        }

        r = smb_session_request(soc:soc, remote:name);
        if(!r)
        {
                close(soc);
                exit(0);
        } 

        prot = smb_neg_prot(soc:soc);
        if(!prot)
        {
                close(soc);
                exit(0);
        }

        r = smb_session_setup(soc:soc, login:login, password:pass,
                              domain:domain, prot:prot);
        if(!r)
        {
                close(soc);
                exit(0);
        }

        uid = session_extract_uid(reply:r);

        r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
        tid = tconx_extract_tid(reply:r);
        if(!tid)
        {
                close(soc);
                exit(0);
        }

        fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
        if(!fid)
        {
                close(soc);
                exit(0);
        }

        v = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:150000);
        return v;
 }

 if(hotfix_check_sp(win2k:5) > 0)
 {
        vers = get_version();
        if(vers == NULL){
                exit(0);
        }

	# Grep < 2000.2.3550.0
        if(ereg(pattern:"^(1999\..*|2000\.(1\..*|2\.([0-2]?[0-9].|3[0-4].*|" +
			"35[0-4][0-9]\..*)))$",	string:vers)){
                security_hole(0);
	}
 }

 if(hotfix_check_sp(xp:4) > 0)
 {
        vers = get_version();
        if(vers == NULL){
                exit(0);
        }

        SP = get_kb_item("SMB/WinXP/ServicePack");
	if("Service Pack 2" >< SP)
        {
		# Grep < 2001.12.4414.320
		if(ereg(pattern:"^(2000\..*|2001\.(0?[0-9]\..*|1[01]\..*|12\." +
			        "([0-3]?[0-9].*|4[0-3].*|440[0-9]\..*|441[0-3]" +
			        "\..*|4414\.([0-2]?[0-9]?[0-9]|3[01][0-9])))).?$",
			string:vers)){
                	security_hole(0);
		}
                exit(0);
        }

	if("Service Pack 3" >< SP)
        {
		# Grep < 2001.12.4414.706
		if(ereg(pattern:"^(2000\..*|2001\.(0?[0-9]\..*|1[01]\..*|12\." +
                                "([0-3]?[0-9].*|4[0-3].*|440[0-9]\..*|441[0-3]" +
                                "\..*|4414\.([0-6]?[0-9]?[0-9]|70[0-5])))).?$", 
                        string:vers)){
                        security_hole(0);
                }
                exit(0);
	}
	else security_hole(0);
 }

 if(hotfix_check_sp(win2003:3) > 0)
 {
        vers = get_version();
        if(vers == NULL){
                exit(0);
        }

	SP = get_kb_item("SMB/Win2003/ServicePack");
	if("Service Pack 1" >< SP)
        {
		# Grep < 2001.12.4720.3129
		if(ereg(pattern:"^(2000\..*|2001\.(0?[0-9]\..*|1[01]\..*|12\." +
                                "([0-3]?[0-9].*|4[0-6].*|47[01][0-9]\..*|4720" +
				"\.([0-2]?[0-9]?[0-9]?[0-9]|30.*|31[01][0-9]|" +
				"312[0-8])))).?$", string:vers)){
                        security_hole(0);
                }
                exit(0);
        }

	if("Service Pack 2" >< SP)
        {
		# Grep < 2001.12.4720.4282
		if(ereg(pattern:"^(2000\..*|2001\.(0?[0-9]\..*|1[01]\..*|12\." +
                                "([0-3]?[0-9].*|4[0-6].*|47[01][0-9]\..*|4720" +
                                "\.([0-3]?[0-9]?[0-9]?[0-9]|4[01].*|42[0-7][0-9]|" +
                                "428[01])))).?$", string:vers)){
                        security_hole(0);
                }
                exit(0);
        }
        else security_hole(0);
 }

## Get the 'Es.dll' path for Windows Vista and 2008 Server
dllPath = registry_get_sz(item:"PathName",
          key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:dllPath + "\system32\Es.dll");
dllVer = GetVer(file:file, share:share);
if(dllVer)
{
  # Windows Vista
  if(hotfix_check_sp(winVista:2) > 0)
  {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP)
    {
      # Grep for Es.dll version < 2001.12.6931.18057
      if(version_is_less(version:dllVer, test_version:"2001.12.6931.18057")){
          security_hole(0);
      }
         exit(0);
    }
  }

  # Windows Server 2008
  else if(hotfix_check_sp(win2008:2) > 0)
  {
    SP = get_kb_item("SMB/Win2008/ServicePack");
    if("Service Pack 1" >< SP)
    {
      # Grep for Es.dll version < 2001.12.6931.18057
      if(version_is_less(version:dllVer, test_version:"2001.12.6931.18057")){
          security_hole(0);
      }
         exit(0);
    }
  }
}

 