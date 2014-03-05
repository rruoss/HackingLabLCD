# OpenVAS Vulnerability Test
# $Id: spybot_detection.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Spybot Search & Destroy Detection
#
# Authors:
# Josh Zlatin-Amishav and Tenable Network Security
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav and Tenable Network Security
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
tag_summary = "The remote Windows host has a spyware detection program installed on it.

Description :

The remote Windows host is running Spybot Search & Destroy, a privacy 
enhancing application that can detect and remove spyware of different 
kinds from your computer.";

 desc = "
 Summary:
 " + tag_summary;

if(description)
{
 script_id(80045);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Spybot Search & Destroy Detection";
 script_name(name);

 script_description(desc);

 summary = "Checks whether Spybot Search & Destroy is installed";

 script_summary(summary);
 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2006 Josh Zlatin-Amishav and Tenable Network Security");
 family = "Service detection";
 script_family(family);

 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.safer-networking.org/");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("global_settings.inc");

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
    tmp = registry_get_sz(item:"DisplayName", key:key + entry);

    if("Spybot" >< tmp) {

       version = registry_get_sz(item:"DisplayVersion", key:key + entry);
       if(!isnull(version)) {
	 set_kb_item(name:"SMB/SpybotSD/version", value:version);
       } 

       path = registry_get_sz(item:"InstallLocation", key:key + entry);
       
       if(path) {
         path += "Updates";
	 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
	 path  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);
         file = path + "\downloaded.ini";
       
	 contents = read_file(file:file, share:share, offset:0, count:85);

	 if(contents && "ReleaseDate" >< contents) {

	    sigs_target = strstr(contents, "ReleaseDate=");
            if (strlen(sigs_target) >= 22) sigs_target = substr(sigs_target, 12, 22);
	    if (isnull(sigs_target)) sigs_target = "n/a";

	    if (sigs_target =~ "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]") {
	        a = split(sigs_target, sep:"-", keep:0);
		sigs_target_yyyymmdd = string(a[0], a[1], a[2]);
		sigs_target_mmddyyyy = string(a[1], "/", a[2], "/", a[0]);
	    }
	    else sigs_target_mmddyyyy = "n/a";

            if(version && sigs_target_mmddyyyy) {
            
               report = string(
                               desc,
                               "\n\n",
                               "Plugin output :\n\n",
                               "Version    : ", version, "\n",
                               "Signatures : ", sigs_target_mmddyyyy);
          
               if(report_verbosity > 0) {
                  security_note(port:port, data:report);
                  exit(0);
               }
           }
	 }  
       }
     break;
    }  
 }

exit(0);
