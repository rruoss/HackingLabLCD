###################################################################
# OpenVAS Network Vulnerability Test
#
# SMB NativeLanMan
#
# LSS-NVT-2009-011
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_summary = "It is possible to extract OS, domain and SMB server information
from the Session Setup AndX Response packet which is generated
during NTLM authentication.";

desc = "
 Summary:
 " + tag_summary;
if (description) {
 script_id(102011);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-09-18 16:06:42 +0200 (Fri, 18 Sep 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("SMB NativeLanMan");

 script_description(desc);
 script_summary("Extracts info about the OS through NTLM authentication packets");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("Copyright (C) 2009 LSS");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include ("misc_func.inc");
include ("smb_nt.inc");
include ("global_settings.inc");
include ("host_details.inc");
include ("cpe.inc");


SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.102011";
SCRIPT_DESC = "Extracts info about the OS through NTLM authentication packets";

port = kb_smb_transport();
if(!port){
 port = 139;
}

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc){
 exit(0);
}

r = smb_session_request(soc:soc, remote:name);
if(!r){
 close(soc);
 exit(0);
}

r = smb_neg_prot_NTLMv1(soc);
r = smb_session_setup_NTLMvN(soc, "anonymous", "password", "domain", "cs", "version");
close (soc);

s = hexstr(r);  # convert response packet to a "string" hex
l = strlen(s);
c = 0;          # counter

# according to www.snia.org/tech_activities/CIFS/CIFS-TR-1p00_FINAL.pdf
# domain, server & os info are the last 3 strings in the packet
# so there is no point in going through the whole packet

for (x=l-3; x>0 && c<3 ; x=x-2) {
 if ( (s[x]+s[x-1]) == "00") {
  c++;
  if (c==1) {
   wg_str = hex2raw(s:out);
   
   if(wg_str && !isnull(wg_str)) {
     set_kb_item (name:"SMB/workgroup", value:wg_str);
     set_kb_item (name:"SMB/DOMAIN", value:wg_str);
     info="Detected SMB workgroup: "+wg_str+'\n';
     desc+=info;
     report = TRUE;
   }  
  }
  if (c==2) {
   smb_str = hex2raw(s:out);

   if(smb_str && !isnull(smb_str)) {
     set_kb_item(name:"SMB/NativeLanManager", value:smb_str);
     set_kb_item(name:"SMB/SERVER", value:smb_str);
     info="Detected SMB server: "+smb_str+'\n';
     desc+=info;
     report = TRUE;
   }

   if ("samba" >< tolower(smb_str)) {
     cpe = build_cpe(value:smb_str, exp:"Samba ([0-9.]+)", base:"cpe:/a:samba:samba:");
     if (!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
   }
  }
  if (c==3) {
   os_str = hex2raw(s:out);
   
   if(os_str && !isnull(os_str)) {
     set_kb_item(name:"Host/OS/smb", value:os_str);
     set_kb_item(name:"SMB/OS", value:os_str);
     info="Detected OS: "+os_str+'\n';
     desc+=info;
     report = TRUE;

     register_host_detail(name:"OS", value:os_str, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     if ("windows" >< tolower(os_str)) {
       register_host_detail(name:"OS", value:"cpe:/o:microsoft:windows", nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     }

   }  

   if(report_verbosity && report) {
     log_message(port:port, data:desc);
   }
  }
  out = NULL;
 } else {
  out = s[x-1] + s[x] + out;
 }
}

