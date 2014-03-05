##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_reg_enum.nasl 42 2013-11-04 19:41:32Z jan $
# Description: Enumerates List of Windows Hotfixes
#
# Authors:
# Chandan S <schandan@secpod.com>
# 
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-08-18
#  - Updated the code to support Windows Vista hotfixes.
#  - Updated the code to support Windows 7.
#  - Updated the code to support Windows server 2008.
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
tag_summary = "This script will enumerates the list of all installed hotfixes
 on the remote host and sets Knowledge Base.";

if(description)
{
 script_id(900012);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_category(ACT_GATHER_INFO);
 script_name("Enumerates List of Windows Hotfixes");
 script_family("Windows");
 script_summary("Check for Hotfixes and set KB List");
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl", "smb_reg_service_pack.nasl","smb_nativelanman.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/registry_access");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


 include("smb_nt.inc");
 include("secpod_smb_func.inc");


 if(get_kb_item("SMB/samba")){
	exit(0);
 }

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)exit(0);

 if(get_kb_item("SMB/Registry/Enumerated")){
	exit(0);
 }

 global_var handle;

 function crawlLevel(key, level, maxlevel)
 {
	list = make_list();
	
	if(level >= maxlevel){
		return list;
	}

	key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe,
				 key:key, reply:handle);
	if(key_h)
	{
		entries = registry_enum_key(soc:soc, uid:uid, tid:tid,
					    pipe:pipe, reply:key_h);
		registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe,
			       reply:key_h);
	}

	foreach item (entries){
		list = make_list(list, key + "\" + item);
	}
	return list;
 }

 function crawl(key, level, maxlevel)
 {
	enum = make_list();

	if(level >= maxlevel){
                return enum;
        }

	enumList = crawlLevel(key, level, maxlevel);
	if(max_index(enumList) > 0){
		enum = make_list(enum, enumList);
	}

        foreach item (enumList)
        {
                listLevel1 = crawlLevel(key:item, level:level+1, maxlevel:maxlevel);
                if(max_index(listLevel1) > 0){
			enum = make_list(enum, listLevel1);
		}

                foreach item (listLevel1)
                {
                        listLevel2 = crawlLevel(key:item, level:level+1, maxlevel:maxlevel);
                        if(max_index(listLevel2) > 0){
				enum = make_list(enum, listLevel2);
			}
                }
        }
        return enum;
 }


 # Script code starts here

 name = kb_smb_name();
 if(!name){
	exit(0);
 }

 port = kb_smb_transport();
 if(!port){
	exit(0);
 }

 if(!get_port_state(port)){
	exit(0);
 }

 login  = kb_smb_login();
 pass   = kb_smb_password();
 domain = kb_smb_domain();

 if(!login){
	login = "";
 }
 if(!pass){
	pass = "";
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

 r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
		       prot:prot);
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
 r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!r)
 {
	close(soc);
	exit(0);
 }

 handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
 location1 = "SOFTWARE\Microsoft\Updates";
 location2 = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix";

 list = make_list(crawl(key:location1, level:0, maxlevel:3),
                  crawl(key:location2, level:0, maxlevel:1));

 if(max_index(list) > 0){
	set_kb_item(name:"SMB/Registry/Enumerated", value:TRUE);
 }

 foreach item ( list )
 {
	if(egrep(pattern:"\\(KB|Q|M)[0-9]+", string:item))
	{
		item = str_replace(find:"\", replace:"/", string:item);
		name = "SMB/Registry/HKLM/" + item;
		set_kb_item(name:name, value:TRUE);
	}
 }

## Check for Windows Vista, Windows 7, windows 2008
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  Name = registry_get_sz(key:key + item , item:"InstallName");
  if(egrep(pattern:"\KB[0-9]+", string:Name))
  {
        path = key +item + Name ;
        Name = str_replace(find:"\", replace:"/", string:path);
        name = "SMB/Registry/HKLM/" + Name ;
        set_kb_item(name:name, value:TRUE);
  }
}
