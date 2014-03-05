###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-040.nasl 16 2013-10-27 13:09:52Z jan $
#
# MS SQL Server Elevation of Privilege Vulnerabilities (941203)
#
# Authors:      Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code,
  with a crafted SQL expression or Exposure of sensitive information or
  Privilege escalation.
  Impact Level: System";
tag_affected = "Microsoft SQL Server 2000 Service Pack 4
  Microsoft SQL Server 2005 Service Pack 2
  Microsoft SQL Server 2005 Edition Service Pack 2
  Microsoft SQL Server 2005 Express Edition Service Pack 2
  Microsoft SQL Server 2005 Express Edition with Advanced Services Service Pack 2";
tag_insight = "The flaws are due to
  - error when initializing memory pages, while reallocating memory.
  - buffer overflow error in the convert function, while handling malformed
    input strings.
  - memory corruption error, while handling malformed data structures in
    on-disk files.
  - buffer overflow error, while processing malformed insert statements.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms08-040.mspx";
tag_summary = "This host has Microsoft SQL Server, which is prone to Privilege
  Escalation Vulnerabilities.";

if(description)
{
  script_id(800105);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-14 16:26:50 +0200 (Tue, 14 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-0085", "CVE-2008-0086", "CVE-2008-0106",
                "CVE-2008-0107");
  script_bugtraq_id(30119);
  script_xref(name:"CB-A", value:"08-0110");
  script_name("MS SQL Server Elevation of Privilege Vulnerabilities (941203)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30970");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2022");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-040.mspx");

  script_description(desc);
  script_summary("Check for the version of MS SQL Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "mssqlserver_detect.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

function Get_FileVersion(ver, path)
{
  if(ver == "MS SQL Server 2005")
  {
    item = "SQLBinRoot";
    file = "\sqlservr.exe";
    offset = 28000000;
  }

  if(ver == "MS SQL Server 2000")
  {
    item = "InstallLocation";
    file = "\Binn\sqlservr.exe";
    offset = 7800000;
  }

  sqlFile = registry_get_sz(key:path ,item:item);
  if(!sqlFile){
    exit(0);
  }

  sqlFile += file;
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:sqlFile);
  file =  ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:sqlFile);

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

  v = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"prod",
                 offset:offset);
  close(soc);
  return v;
}

mssql_port = get_kb_item("Services/mssql");
if(!mssql_port){
  mssql_port = 1433;
}

if(!get_port_state(mssql_port)){
  exit(0);
}

# Retrieving Microsoft SQL Server 2005 Registry entry
if(registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                           "\Uninstall\Microsoft SQL Server 2005")){
  msSqlSer = "MS SQL Server 2005";
}
# Retrieving Microsoft SQL Server 2000 Registry entry
else if (registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\Uninstall\Microsoft SQL Server 2000")){
  msSqlSer = "MS SQL Server 2000";
}

if(!msSqlSer){
  exit(0);
}

if(msSqlSer == "MS SQL Server 2005"){
  reqSqlVer = "9.00.3068.00";
  insSqlVer = Get_FileVersion(ver:msSqlSer, path:"SOFTWARE\Microsoft" +
                                "\Microsoft SQL Server\MSSQL.1\Setup");
}
else if(msSqlSer == "MS SQL Server 2000"){
  reqSqlVer = "8.00.2050";
  insSqlVer = Get_FileVersion(ver:msSqlSer, path:"SOFTWARE\Microsoft\Windows" +
                        "\CurrentVersion\Uninstall\Microsoft SQL Server 2000");
}

if(!insSqlVer){
  exit(0);
}

if(version_is_greater(version:reqSqlVer, test_version:insSqlVer)){
  security_hole(0);
}
