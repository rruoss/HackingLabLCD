##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_org_chart_remote_code_exe_vuln_900120.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Microsoft Organization Chart Remote Code Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Enticing the victim into opening a malicious crafted
        Organization Chart document, remote attackers can crash the application
        or execute arbitrary code on the affected system within the context
        of the affected application.
 Impact Level : Application";

tag_solution = "No solution or patch is available as of 10th September, 2008. Information
 regarding this issue will be updated once the solution details are available.
 For updates check, http://office.microsoft.com/en-us/ork2003/HA011402441033.aspx";

tag_affected = "MS Organization Chart versions 2.0 (11.0.5614.0) and prior on Windows (all).";

tag_insight = "Microsoft Organization Chart is prone to a remote code execution 
        vulnerability. The flaw is due to memory access violation 
        error when opening malicious Organization Chart document.";


tag_summary = "The host has Microsoft Organization Chart, which is prone to a
 remote code execution vulnerability.";


if(description)
{
 script_id(900120);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
 script_cve_id("CVE-2008-3956");
 script_bugtraq_id(31059);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_category(ACT_GATHER_INFO);
 script_family("Windows");
 script_name("Microsoft Organization Chart Remote Code Execution Vulnerability");
 script_summary("Check for vulnerable version and prior of Microsoft Organization Chart");
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

 script_description(desc);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/31059/discuss");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/31059/exploit");
 script_xref(name : "URL" , value : "http://www.nullcode.com.ar/ncs/crash/orgchart.htm");
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
 include("secpod_smb_func.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 name = kb_smb_name();
 domain = kb_smb_domain();
 login = kb_smb_login();
 pass = kb_smb_password();
 port = kb_smb_transport();

 soc = open_sock_tcp(port);
 if(!soc){
        exit(0);
 }

 r = smb_session_request(soc:soc, remote:name);
 if(!r){
        close(soc);
        exit(0);
 }

 prot = smb_neg_prot(soc:soc) ;
 if(!prot){
        close(soc);
        exit(0);
 }

 r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
                            prot:prot);
 if(!r){
	close(soc);
        exit(0);
 }

 uid = session_extract_uid(reply:r);
 r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");

 tid = tconx_extract_tid(reply:r);
 if (!tid){
        close(soc);
        exit(0);
 }

 r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
 if(!r){
        close(soc);
        exit(0);
 }

 pipe = smbntcreatex_extract_pipe(reply:r);
 if(!pipe){
        close(soc);
        exit(0);
 }

 r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!r){
        close(soc);
        exit(0);
 }

 handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!handle){
        close(soc);
        exit(0);
 }

 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
 msOrgKey = registry_get_key(soc:soc, uid:uid ,tid:tid ,pipe:pipe,key:key,
                                 reply:handle);
 if(!msOrgKey){
	close(soc);
        exit(0);
 }

 entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, 
                                 reply:msOrgKey);
 close(soc);

 foreach entry (entries)
 {
        msOrgName = registry_get_sz(key:key + entry, item:"DisplayName");
        
	if("Microsoft Organization Chart 2.0" >< msOrgName)
        {
                msOrgVer = registry_get_sz(key:key + entry, 
                                           item:"DisplayVersion");

		# Grep for version <= 11.0.5614.0
                if(egrep(pattern:"^(([0-9]|10)\..*|11\.0\.([0-4]?[0-9]?[0-9]?[0-9]" +
				 "|5[0-5][0-9][0-9]|560[0-9]|561[0-4])\.0)$",
			 string:msOrgVer)){
			security_hole(0);
                }
                exit(0);
        }
 }
