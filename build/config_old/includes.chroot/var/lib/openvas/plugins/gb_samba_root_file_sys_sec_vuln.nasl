###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_root_file_sys_sec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Samba Root File System Access Security Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful local exploitation could result in bypassing certain
  security restrictions by malicious users.
  Impact Level: System";
tag_affected = "Samba 3.2.0 through 3.2.6 on Linux.";
tag_insight = "Access to the root file system is granted when authenticated users connect
  to a share with an empty string as name.";
tag_solution = "Upgrade to 3.2.7 of Samba,
  http://us3.samba.org/samba/";
tag_summary = "The host has Samba installed and is prone to System Access Security
  Vulnerability.";


if(description)
{
  script_id(800404);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-0022");
  script_bugtraq_id(33118);
  script_name("Samba Root File System Access Security Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33379");
  script_xref(name : "URL" , value : "http://liudieyu0.blog124.fc2.com/blog-entry-6.html");
  script_xref(name : "URL" , value : "http://us1.samba.org/samba/security/CVE-2009-0022.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/497091/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("smb_nativelanman.nasl","gb_samba_detect.nasl");
  script_require_keys("Samba/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

smbVer = get_kb_item("Samba/Version");

if(!smbVer){
  if(!lanman = get_kb_item("SMB/NativeLanManager"))exit(0);
  if("Samba" >!< lanman)exit(0);
  if(!version = eregmatch(pattern:"Samba ([0-9.]+)", string: lanman))exit(0);
  if(isnull(version[1]))exit(0);
  smbVer = version[1];
}

if(!smbVer){
  exit(0);
}  

if(version_in_range(version:smbVer, test_version:"3.2", test_version2:"3.2.6")){
  security_hole(0);
}


