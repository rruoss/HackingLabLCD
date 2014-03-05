##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ultra_office_activex_control_mult_vuln_900208.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Ultra Office ActiveX Control Multiple Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2011-07-18
#   - Added null check
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
tag_impact = "Successful exploitation will allow execution of arbitrary
        code, stack-based buffer overflow, can overwrite arbitrary files
        on the vulnerable system by tricking a user into visiting a
        malicious website.
 Impact Level : Application";

tag_solution = "No solution or patch is available as of 01st September, 2008. Information
 regarding this issue will be update once the solution details are available.
 For updates refer to http://www.ultrashareware.com/Ultra-Office-Control.htm

 Quick Fix: Set a kill bit for the CLSID's
 {00989888-BB72-4E31-A7C6-5F819C24D2F7}

 Refer to following link to set kill-bit,
 http://support.microsoft.com/kb/240797";

tag_affected = "Ultra Office Control 2.x and prior versions on Windows (All).";

tag_insight = "Error exists when handling parameters received by the HttpUpload()
        and Save() methods in OfficeCtrl.ocx file.";


tag_summary = "This host is running Ultra Office Control, which is prone to
 multiple vulnerabilities.";


if(description)
{
 script_id(900208);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
 script_cve_id("CVE-2008-3878");
 script_bugtraq_id(30861);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_name("Ultra Office ActiveX Control Multiple Vulnerabilities");
 script_summary("Check for Vulnerable Version of Ultra Office");
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
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31632/");
 script_xref(name : "URL" , value : "http://www.juniper.net/security/auto/vulnerabilities/vuln30861.html");
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

 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
 key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe,
                          key:key, reply:handle);
 if(!key_h)
 {
        close(soc);
        exit(0);
 }

 # To get application installed Path.
 enumKeys = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);
 close(soc);

 foreach entry (enumKeys)
 {
        if("Ultra Office Control" >< entry)
        {
                appInsLoc = registry_get_sz(item:"InstallLocation", key:key + entry);
                if(!appInsLoc){
                        exit(0);
                }
		break;
        }
 }

 if(!appInsLoc){
   exit(0);
 }

 # To Get File Version.
 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:appInsLoc);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:appInsLoc + "OfficeCtrl.ocx");

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

 r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
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

 fileVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid);
 close(soc);

 if(!fileVer){
	exit(0);
 }

 # Grep for Version <= 2.0.2008.801  
 if(egrep(pattern:"^([01]\..*|2\.0\.[01]?[0-9]?[0-9]?[0-9]\..*|2\.0\.200[0-7]" +
		  "\..*|2\.0\.2008(\.[0-7]?[0-9]?[0-9]|\.80[01]))$", string:fileVer))
 {
        clsid = "{00989888-BB72-4E31-A7C6-5F819C24D2F7}";
        regKey = "SOFTWARE\Classes\CLSID\"+ clsid;
        if(registry_key_exists(key:regKey))
        {
                # Check for Kill-Bit set for ActiveX control
                activeKey = "SOFTWARE\Microsoft\Internet Explorer\"+
                            "ActiveX Compatibility\" + clsid;
                killBit = registry_get_dword(key:activeKey,
                          		     item:"Compatibility Flags");
                if(killBit && (int(killBit) == 1024)){
                        exit(0);
                }
                security_hole(0);        
        }
 }
