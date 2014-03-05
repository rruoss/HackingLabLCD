##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wingate_imap_dos_vuln_900201.nasl 16 2013-10-27 13:09:52Z jan $
# Description: WinGate IMAP Server Buffer Overflow Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Exploiting this issue will consume computer resources and deny
        access to legitimate users or to potentially compromise a vulnerable
        system or may allow execution of arbitrary code.
 Impact Level : Application";

tag_solution = "No solution or patch is available as of 14th August, 2008. Information
 regarding this issue will update once the solution details are available.
 For updates refer to http://www.wingate.com/download/wingate/download.php";

tag_affected = "WinGate 6.2.2 and prior versions on Windows (All).";

tag_insight = "The vulnerability is due to a boundary error in the processing 
        of IMAP commands. This can be exploited by issuing an IMAP LIST command
        with an overly long argument.";


tag_summary = "This host is running Qbik WinGate, which is prone to Denial of
 Service Vulnerability.";


if(description)
{
 script_id(900201);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3606");
 script_bugtraq_id(30606);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("WinGate IMAP Server Buffer Overflow Vulnerability");
 script_summary("Check for the version of WinGate");
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
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31442/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/495264");
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
 include("imap_func.inc");

 winPort = get_kb_item("Services/imap");
 if(!winPort){
        winPort = 143;
 }

 if(!get_port_state(winPort)){
        exit(0);
 }

 if("WinGate" >!< get_imap_banner(port:winPort)){
        exit(0);
 }

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 name   =  kb_smb_name();
 login  =  kb_smb_login();
 pass   =  kb_smb_password();
 domain =  kb_smb_domain();
 port   =  kb_smb_transport();

 if(!port) port = 139;

 if(!get_port_state(port))exit(0);

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
 r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
 tid = tconx_extract_tid(reply:r);
 if(!tid)
 {
        close(soc);
        exit(0);
 }

 r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
 if(!r)
 {
        close(soc);
        exit(0);
 }

 pipe = smbntcreatex_extract_pipe(reply:r);
 if(!pipe)
 {
        close(soc);
        exit(0);
 }

 r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!r)
 {
        close(soc);
        exit(0);
 }

 handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!handle)
 {
        close(soc);
        exit(0);
 }

 handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!handle)
 {
        close(soc);
        exit(0);
 }

 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
 key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe,
                          key:key, reply:handle);
 if(!key_h)
 {
 	exit(0);
 }
 
 enumKeys = registry_enum_key(soc:soc, uid:uid, tid:tid,
                              pipe:pipe, reply:key_h);

 foreach entry (enumKeys)
 {
 	if("WinGate" >< entry)
	{
		winGateName = registry_get_sz(item:"DisplayName",
                                              key:key + entry);
                if(winGateName)
		{
			if(egrep(pattern:"WinGate 6\.[01](\..*)?|6\.2(\.[0-2])?$",
					  string:winGateName)) {
				security_hole(winPort);
			}
		}
 		exit(0);
	}
 }
