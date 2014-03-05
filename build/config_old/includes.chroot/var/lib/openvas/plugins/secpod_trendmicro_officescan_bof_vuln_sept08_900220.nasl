##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trendmicro_officescan_bof_vuln_sept08_900220.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Trend Micro OfficeScan Server cgiRecvFile.exe Buffer Overflow Vulnerability
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
tag_impact = "Remote exploitation could allow execution of arbitrary code to
        cause complete compromise of system and failed attempt leads to denial
        of service condition.
 Impact Level : Application/System.";

tag_solution = "Partially Fixed.
 Fix is available for Trend Micro OfficeScan 8.0, 7.3 and
 Client Server Messaging Security (CSM) 3.6.

 Apply patch Trend Micro OfficeScan Corporate Edition 8.0 from
 http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_Win_EN_CriticalPatch_B1361.exe
 http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Win_EN_CriticalPatch_B2424.exe
 http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Patch1_Win_EN_CriticalPatch_B3060.exe

 Apply patch Trend Micro OfficeScan Corporate Edition 7.3 from
 http://www.trendmicro.com/ftp/products/patches/OSCE_7.3_Win_EN_CriticalPatch_B1367.exe

 Apply patch Trend Micro Client Server Messaging Security (CSM) 3.6 from
 http://www.trendmicro.com/ftp/products/patches/CSM_3.6_OSCE_7.6_Win_EN_CriticalPatch_B1195.exe";


tag_affected = "Trend Micro OfficeScan Corporate Edition version 8.0
        Trend Micro OfficeScan Corporate Edition versions 7.0 and 7.3
        Trend Micro Client Server Messaging Security (CSM) for SMB versions 2.x and 3.x";

tag_insight = "The flaw is due to error in cgiRecvFile.exe can be exploited
        to cause a stack based buffer overflow by sending a specially crated
        HTTP request with a long ComputerName parameter.";


tag_summary = "This Remote host is installed with Trend Micro OfficeScan, which
 is prone to Buffer Overflow Vulnerability.";

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


if(description)
{
 script_id(900220);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
 script_bugtraq_id(31139);
 script_cve_id("CVE-2008-2437");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_name("Trend Micro OfficeScan Server cgiRecvFile.exe Buffer Overflow Vulnerability.");
 script_summary("Check for the version of Trend Micro OfficeScan");
 script_description(desc);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31342/");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Sep/1020860.html");
 script_xref(name : "URL" , value : "http://www.juniper.net/security/auto/vulnerabilities/vuln31139.html");
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

 scanVer = registry_get_sz(key:"SOFTWARE\TrendMicro\OfficeScan\service" + 
                               "\Information", item:"Server_Version");
 if(!scanVer){
	exit(0);
 }

 if(!egrep(pattern:"^([0-7]\..*|8\.0)$", string:scanVer)){
	exit(0);
 }

 offPath = registry_get_sz(key:"SOFTWARE\TrendMicro\OfficeScan\service" +
                               "\Information", item:"Local_Path");
 if(!offPath){
	exit(0);
 }

 report = string("\n *****\n NOTE : Ignore this warning if the above mentioned" + 
                 "patch is already applied.\n *****\n");

 # For Trend Micro Client Server Messaging Security and Office Scan 8 or 7.0
 if(registry_key_exists(key:"SOFTWARE\TrendMicro\CSM") || 
                        scanVer =~ "^(8\..*|[0-7]\.[0-2](\..*)?)$"){
        security_hole(data:string(desc, report));
        exit(0);
 }

 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:offPath);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", 
                      string:offPath + "Web\CGI\cgiRecvFile.exe");

 name    =  kb_smb_name();
 login   =  kb_smb_login();
 pass    =  kb_smb_password();
 domain  =  kb_smb_domain();
 port    =  kb_smb_transport();

 if(!port){
	port = 139;
 }

 if(!get_port_state(port)){
        exit(0);
 }
 
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

 fileVersion = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid);
 if(!fileVersion){
        exit(0);
 }

 # grep for file version < 7.3.0.1367
 if(egrep(pattern:"^7\.3\.0\.(0?[0-9]?[0-9]?[0-9]|1[0-2][0-9][0-9]|" +
                  "13[0-5][0-9]|136[0-6])$", string:scanVer)){
        security_warning(0);
 }
