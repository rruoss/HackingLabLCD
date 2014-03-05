##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-050_900034.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Windows Messenger Could Allow Information Disclosure Vulnerability (955702
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
tag_impact = "Remote attackers can log on to a user's Messenger client as a user,
        and can initiate audio and video chat sessions without user interaction.
 Impact Level : Network";

tag_solution = "Run Windows Update and update the listed hotfixes or download and
 update mentioned hotfixes in the advisory from the below link,
 http://www.microsoft.com/technet/security/bulletin/ms08-050.mspx";

tag_affected = "Windows Messenger 4.7 on MS Windows 2K/XP
        Windows Messenger 5.1 on MS Windows 2K/XP/2003";

tag_insight = "Issue is in the Messenger.UIAutomation.1 ActiveX control being marked
        safe-for-scripting, which allows changing state, obtain contact information
        and a user's login ID.";


tag_summary = "This host is missing a critical security update according to
 Microsoft Bulletin MS08-050.";

if(description)
{
 script_id(900034);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
 script_bugtraq_id(30551);
 script_cve_id("CVE-2008-0082");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_category(ACT_GATHER_INFO);
 script_family("Windows : Microsoft Bulletins");
 script_name("Windows Messenger Could Allow Information Disclosure Vulnerability (955702)");
 script_summary("Check for the Hotfix and version of Winndows Messenger");
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
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-050.mspx");
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
 include("secpod_smb_func.inc");

 if(hotfix_check_sp(xp:3, win2k:5, win2003:3) <= 0){
	 exit(0);
 }

 function get_version()
 {
	dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Active Setup\Installed Components" +
                                      "\{5945c046-1e7d-11d1-bc44-00c04fd912be}",
                                  item:"KeyFileName");

        dllPath = dllPath - "msmsgs.exe" + "msgsc.dll";

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

        v = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:60000);
        return v;
 }

 if(!registry_key_exists(key:"SOFTWARE\Clients\IM\Windows Messenger")){
	exit(0);
 }

 msngrVer = registry_get_sz(key:"SOFTWARE\Microsoft\Active Setup\Installed Components" +
		                "\{5945c046-1e7d-11d1-bc44-00c04fd912be}",
		  	    item:"Version");
 if(!msngrVer){
	exit(0);
 }

 if("5.1" >< msngrVer)
 {
	if(hotfix_missing(name:"899283") == 0){
                exit(0);
        }

	vers = get_version();
        if(vers == NULL){
                exit(0);
        }

	# Grep < 5.1.0715
        if(ereg(pattern:"^5\.1\.0?([0-6]?[0-9]?[0-9]|70[0-9]|71[0-4])0?$", string:vers)){
                security_hole(0);
	}
        exit(0);
 }

 else if("4,7" >< msngrVer)
 {
 	if(hotfix_check_sp(xp:4) > 0)
 	{
		if(hotfix_missing(name:"946648") == 0){
                	exit(0);
        	}
	}

	else if(hotfix_check_sp(win2003:3) > 0)
	{
		if(hotfix_missing(name:"954723") == 0){
                        exit(0);
                }
	}

        vers = get_version();
        if(vers == NULL){
               	exit(0);
        }

	# Grep < 4.7.3002
	if(ereg(pattern:"^4\.7\.([0-2]?[0-9]?[0-9]?[0-9]|300[01])0?$", string:vers)){
               	security_hole(0);
	}
 }
