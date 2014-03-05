###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_smb_accessible_shares.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Windows SMB Accessible Shares
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
###############################################################################

include("revisions-lib.inc");
tag_summary = "The script detects the Windows SMB Accessible Shares and sets the
  result into KB.";

if(description)
{
  script_id(902425);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-29 12:08:36 +0530 (Wed, 29 Feb 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Microsoft Windows SMB Accessible Shares");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for SMB Accessible Shares");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Windows");
  script_dependencies("smb_login.nasl");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");



name = "";
domain = "";
port = "";
login = "";
pass = "";
soc = "";
r = "";
prot = "";
uid = "";
tid = "";

name = kb_smb_name();
domain = kb_smb_domain();
port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();

## Get the SMB Port
if(!port){
  port = 139;
}

## Check the port status
if(!get_port_state(port)){
 exit(0);
}

## Open the tcp socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Session request
r = smb_session_request(soc:soc, remote:name);
if(!r)
{
  close(soc);
  exit(0);
}

## Get the protocol
prot = smb_neg_prot(soc:soc);
if(!prot)
{
  close(soc);
  exit(0);
}

## Start the session
r = smb_session_setup(soc:soc, login:login, password:pass ,domain:"", prot:prot);
if(!r)
{
  r = smb_session_setup(soc:soc, login:"anonymous", password:pass ,domain:"", prot:prot);
  if(!r)
  {
    close(soc);
    exit(0);
  }
}

## Get the uid
uid = session_extract_uid(reply:r);
foreach s (make_list("A$", "C$", "D$", "ADMIN$", "WINDOWS$", "ROOT$", "WINNT$", "IPC$", "E$"))
{
  r = smb_tconx(soc:soc, name:name, uid:uid, share:s);
  if(r)
  {
    tid = tconx_extract_tid(reply:r);
    if(tid){
      set_kb_item(name:"SMB/Accessible_Shares", value:s);
    }
  }
}

close(soc);
