##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ultraiso_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# UltraISO Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "This script detects the installed version of UltraISO and
  sets the result in KB.";

if(description)
{
  script_id(800274);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("UltraISO Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of UltraISO in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800274";
SCRIPT_DESC = "UltraISO Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ultraName = registry_get_sz(key:key + item, item:"DisplayName");
  if("UltraISO" >< ultraName)
  {
    path = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(path == NULL){
       continue;
    }

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);

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

    v = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:1174636);
    close(soc);
    if(v != NULL)
    {
      set_kb_item(name:"UltraISO/Ver", value:v);
      security_note(data:"UltraISO version " + v + " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:v, exp:"^([0-9.]+)", base:"cpe:/a:ezbsystems:ultraiso:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
