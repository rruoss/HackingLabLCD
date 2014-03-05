###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avant_browser_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Avant Browser Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script detects the installed version of Avant Browser
  and sets the result in KB.";

if(description)
{
  script_id(800870);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Avant Browser Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Avant Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  return NULL;
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800870";
SCRIPT_DESC = "Avant Browser Version Detection";

function AvantGetVersion(file, share)
{
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:file);

  soc = open_sock_tcp(port);
  if(!soc){
    return NULL;
  }

  r = smb_session_request(soc:soc, remote:name);
  if(!r)
  {
    close(soc);
    return NULL;
  }

  prot = smb_neg_prot(soc:soc);
  if(!prot)
  {
    close(soc);
    return NULL;
  }

  r = smb_session_setup(soc:soc, login:login, password:pass,
                        domain:domain, prot:prot);
  if(!r)
  {
    close(soc);
    return NULL;
  }

  uid = session_extract_uid(reply:r);
  r = smb_tconx(soc:soc, name:name, uid:uid, share:share);

  tid = tconx_extract_tid(reply:r);
  if(!tid)
  {
    close(soc);
    return NULL;
  }

  fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
  if(!fid)
  {
    close(soc);
    return NULL;
  }
  avantVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:250000);

  if(avantVer)
    return avantVer;
  else
    return NULL;
}


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AvantBrowser";
avantName = registry_get_sz(key:path, item:"DisplayName");

if("Avant Browser" >< avantName)
{
  avantPath = registry_get_sz(key:path, item:"UninstallString");
  avantPath = eregmatch(pattern:'\"(.*)\"', string:avantPath);
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:avantPath[1]);

  foreach item (make_list("avant.exe", "iexplore.exe", "abrowser.exe"))
  {
    path1 = avantPath[1] - "uninst.exe" + item;
    avantVer = AvantGetVersion(file:path1, share:share);

    if(!isnull(avantVer) && avantVer =~ "^0\.0\..*")
    {
      path2 = avantPath[1] - "uninst.exe" + "abrowser.ini";
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path2);
      read = read_file(file:file, share:share, offset:0, count:20000);
      avantVer = eregmatch(pattern:"VersionInfo=([0-9.]+)", string:read);

      if(!isnull(avantVer[1]))
        avantVer = avantVer[1];
    }

    if(!isnull(avantVer))
    {
      set_kb_item(name:"AvantBrowser/Ver", value:avantVer);
      security_note(data:"Avant Browser version " + avantVer + 
                         " was detected on the host");
    
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:avantVer, exp:"^([0-9.]+)", base:"cpe:/a:avant_force:avant_browser:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
