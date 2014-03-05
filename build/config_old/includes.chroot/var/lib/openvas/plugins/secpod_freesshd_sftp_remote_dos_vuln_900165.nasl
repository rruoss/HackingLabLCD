##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_freesshd_sftp_remote_dos_vuln_900165.nasl 16 2013-10-27 13:09:52Z jan $
# Description: freeSSHd SFTP 'rename' and 'realpath' Remote DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "The host is running freeSSHd SSH server and is prone to
  remote denial of service vulnerability.

  NULL pointer de-referencing errors in SFTP 'rename' and 'realpath' commands.
  These can be exploited by passing overly long string passed as an argument to
  the affected commands.";

tag_impact = "Successful exploitation will cause denial of service.
  Impact Level: Application";
tag_affected = "freeSSHd freeSSHd version 1.2.1.14 and prior on Windows (all)";
tag_solution = "Upgrade to freeSSHd version 1.2.6 or later.
  For updates refer to http://www.freesshd.com/index.php?ctt=download";

if(description)
{
  script_id(900165);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-31 14:50:32 +0100 (Fri, 31 Oct 2008)");
  script_cve_id("CVE-2008-4762");
 script_bugtraq_id(31872);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("freeSSHd SFTP 'rename' and 'realpath' Remote DoS Vulnerability");
  script_summary("Check for vulnerable version of freeSSHd");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://freesshd.com/index.php");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6800");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32366/");

  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl", "ssh_detect.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports("Services/ssh", 22);
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

sshdPort = get_kb_item("Services/ssh");
if(!sshdPort){
  sshdPort = 22;
}

# check if FreeSSHd is listening
banner = get_kb_item("SSH/banner/" + sshdPort);
if("WeOnlyDo" >!< banner || "WeOnlyDo-wodFTPD" >< banner){
  exit(0);
} 

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

sshdPath = registry_get_sz(key:"SYSTEM\CurrentControlSet\Services\FreeSSHDService",
                           item:"ImagePath");
if(!sshdPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sshdPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sshdPath);

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

r = smb_session_request(soc:soc, remote:name);
if(!r){
  close(soc);
  exit(0);
}

prot = smb_neg_prot(soc:soc);
if(!prot){
  close(soc);
  exit(0);
}

r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
                      prot:prot);
if(!r){
  close(soc);
  exit(0);
}

uid = session_extract_uid(reply:r);
if(!uid){
  close(soc);
  exit(0);
}

r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
tid = tconx_extract_tid(reply:r);
if(!tid){
  close(soc);
  exit(0);
}

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(!fid){
  close(soc);
  exit(0);
}

fileVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid);

# Grep for freeSSHd version 1.2.1.14 and prior
if(egrep(pattern:"^1\.([01](\..*)|2(\.[01](\.[0-9]|\.1[0-4])?)?)$", 
         string:fileVer)){
  security_hole(sshdPort);
}
