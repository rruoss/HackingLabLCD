###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Check the IIS Metabase for AspEnableParentPaths (Win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Check the IIS Metabase for AspEnableParentPaths

   This script reads the IIS Metabase an get the 
  AspEnableParentPaths configuration.";

if(description)
{
  script_id(96009);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"Fri Oct 23 12:32:24 2009 +0200");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IIS Metabase");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check the IIS Metabase for AspEnableParentPaths");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
   
  script_dependencies("secpod_reg_enum.nasl", "GSHB_WMI_OSInfo.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

windirpath = get_kb_item("WMI/WMI_OSWINDIR");


if(!windirpath || windirpath >< "error" || windirpath >< "none"){
  set_kb_item(name:"GSHB/AspEnableParentPaths", value:"error");
  set_kb_item(name:"GSHB/AspEnableParentPaths/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}


val01 = split(windirpath, sep:":", keep:0);
win_dir =  val01[1];
win_dir =  ereg_replace(pattern:'\\\\',replace:'', string:win_dir);
share = val01[0] + "$";


file = "\" + win_dir + "\system32\inetsrv\metabase.xml";

name = kb_smb_name();
domain = kb_smb_domain();
login = kb_smb_login();
pass = kb_smb_password();
port = kb_smb_transport();
size = get_file_size(share:share, file:file);

soc = open_sock_tcp(port);

if (!size){
  set_kb_item(name:"GSHB/AspEnableParentPaths", value:"off");
  log_message(port:0, proto: "IT-Grundschutz", data:"IIS Metabase file not found.");
  exit(0);
}

if(!soc){
  set_kb_item(name:"GSHB/AspEnableParentPaths", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:"Cant open socket to Host");
  exit(0);
}

r = smb_session_request(soc:soc, remote:name);
if(!r){
  set_kb_item(name:"GSHB/AspEnableParentPaths", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:"Cannot pre-establish an SMB Session with the remote Host.");
  close(soc);
  exit(0);
}

prot = smb_neg_prot(soc:soc);
if(!prot){
  set_kb_item(name:"GSHB/AspEnableParentPaths", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:"Cannot negociate the protocol");
  close(soc);
  exit(0);
}

r = smb_session_setup(soc:soc, login:login, password:pass,
                       domain:domain, prot:prot);
if(!r){
  set_kb_item(name:"GSHB/AspEnableParentPaths", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:"Cannot setup a SMB session to the remote Host");
  close(soc);
  exit(0);
}

uid = session_extract_uid(reply:r);

r = smb_tconx(soc:soc, name:name, uid:uid, share:share);

tid = tconx_extract_tid(reply:r);
if(!tid){
  set_kb_item(name:"GSHB/AspEnableParentPaths", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:"Cant find Tree ID(tid)");
  close(soc);
  exit(0);
}

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(!fid){
  set_kb_item(name:"GSHB/AspEnableParentPaths", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:"Cant find File ID (fid)");
  close(soc);
  exit(0);
}

metabase = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid,
                           count:size, off:0);
if (!metabase){
   AspEnableParentPaths = "error";
   log_message(port:port, data:"Cannot access/open the IIS Metabase file.");
} else if(egrep(pattern:"AspEnableParentPaths=.TRUE.", string:metabase)){
   AspEnableParentPaths = "on";
} else {
   AspEnableParentPaths = "off";
}
if (!AspEnableParentPaths || AspEnableParentPaths = "") AspEnableParentPaths = "none";

set_kb_item(name:"GSHB/AspEnableParentPaths", value:AspEnableParentPaths);
close(soc);
exit(0);
