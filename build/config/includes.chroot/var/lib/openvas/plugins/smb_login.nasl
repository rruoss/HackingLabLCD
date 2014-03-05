##############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_login.nasl 42 2013-11-04 19:41:32Z jan $
# Description: SMB log in 
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
tag_summary = "This script attempts to logon into the remote host using 
 login/password credentials.";

if(description)
{
 script_id(10394);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2008-09-10 10:22:48 +0200 (Wed, 10 Sep 2008)");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_category(ACT_GATHER_INFO);
 script_family("Windows");
 script_name("SMB log in");
 script_summary("Attempts to log into the remote host");
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_dependencies("smb_authorization.nasl", "netbios_name_get.nasl",
                     "cifs445.nasl", "find_service.nasl", "logins.nasl");
 script_require_keys("SMB/name", "SMB/transport");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


 include("smb_nt.inc");
 
 port = kb_smb_transport();
 if(!port){
	port = 139;
 }

 name = kb_smb_name();
 if(!name){
        name = "*SMBSERVER";
 }

 if(!get_port_state(port)){
        exit(0);
 }

 login =  string(get_kb_item("SMB/login_filled/0"));
 password = string(get_kb_item("SMB/password_filled/0"));
 user_domain = string(get_kb_item("SMB/domain_filled/0"));

 if(!user_domain)
 {
   if('\\' >< login)
   {
     matched_domain = eregmatch(pattern:".*\\",string:login);
     if(!isnull(matched_domain[0]))
     {
       user_domain =  ereg_replace(pattern:"\\", replace:"", string:matched_domain[0]);
     }
   }

   if('@' >< login)
   {
     matched_domain = eregmatch(pattern:"@.*",string:login);
     if(!isnull(matched_domain[0]))
     {
       user_domain =  ereg_replace(pattern:"@", replace:"", string:matched_domain[0]);
       if(user_domain =~ ".*\..*") {
         fqdn_domain = eregmatch(pattern:".*\.",string:user_domain);
         if(!isnull(fqdn_domain[0])){
           user_domain = ereg_replace(pattern:"\.", replace:"", string:fqdn_domain[0]);
         }
       }
     }
   }

 }  
 
 if ('\\' >< login)
 {
   user_login = eregmatch(pattern:"\\.*", string:login);
   if('\\' >< user_login[0]) {
       login =  ereg_replace(pattern:"\\", replace:"", string:user_login[0]);
   }
 }

 if ('@' >< login)
 {
   user_login = eregmatch(pattern:".*@", string:login);
   if('@' >< user_login[0]) {
       login =  ereg_replace(pattern:"@", replace:"", string:user_login[0]);
   }
 }

if(!strlen(login)){
	login ="";
 }

 if(!strlen(password)){
        password = "";
 }

 if(strlen(user_domain)){
	domain = user_domain;
 }

 if(!strlen(user_domain)){
#        user_domain = "";
 
#        soc = open_sock_tcp(port);
#        if(!soc){
#                exit(0);
#        }

#        smb_session_request(soc:soc, remote:name);

#        prot = smb_neg_prot(soc:soc);
#        close(soc);

#        domain = smb_neg_prot_domain(prot:prot);

        domain = string(get_kb_item("SMB/DOMAIN"));
        if(!domain){
                domain = string(get_kb_item("SMB/workgroup"));
        }
        if(!domain){
                domain = "";
        }
 }

 set_kb_item(name:"SMB/login", value:login);
 set_kb_item(name:"SMB/password", value:password);

 if(domain){
        set_kb_item(name:"SMB/domain", value:domain);
 }

 function remote_login(login, passwd, domain)
 {
 	login_defined = 0;

	soc = open_sock_tcp(port);
	if(!soc){
	        return(login_defined);
        }

  	r = smb_session_request(soc:soc, remote:name);
  	if(!r){
		close(soc);
	        return(login_defined);
	}

	prot = smb_neg_prot(soc:soc);
  	if(!prot){
                close(soc);
	        return(login_defined);
        }

  	r = smb_session_setup(soc:soc, login:login, password:password,
			      domain:domain, prot:prot);
  	if(!r){
                close(soc);
                return(login_defined);
        }

    	uid = session_extract_uid(reply:r);
    	r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
 	close(soc);

    	if(r){
		tid = tconx_extract_tid(reply:r);
		login_defined = 1;
	}
    	else{
		login_defined = 0;
 	}
	return(login_defined);
 }

 login_defined = remote_login(login:login, passwd:password, domain:domain);

 if(login_defined == 1)
 {
        report = string("It was possible to log into the remote host using the SMB protocol.\n");
        log_message(data:report, port:port);
 }

 else if((login_defined == 0) && login)
 {
        report = string("It was not possible to log into the remote host using the SMB protocol.\n");
        log_message(data:report, port:port);
 }
