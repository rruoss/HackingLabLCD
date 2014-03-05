###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_senddoc_tmp_file_creation_vuln_lin.nasl 16 2013-10-27 13:09:52Z jan $
#
# OpenOffice senddoc Insecure Temporary File Creation Vulnerability (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to delete or corrupt
  sensitive files, which may result in a denial of service condtion.
  Impact Level: Application";
tag_affected = "OpenOffice.org 2.4.1 on Linux.";
tag_insight = "The flaw exists due to OpenOffice 'senddoc' which creates temporary files
  in an insecure manner, which allows users to overwrite files via a symlink
  attack on a /tmp/log.obr.##### temporary file.";
tag_solution = "Upgrade OpenOffice to higher version.
  http://download.openoffice.org/index.html";
tag_summary = "The host has OpenOffice installed and is prone to Insecure
  Temporary File Creation Vulnerability.";

if(description)
{
  script_id(800129);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-4937");
  script_bugtraq_id(30925);
  script_name("OpenOffice senddoc Insecure Temporary File Creation Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2008/10/30/2");
  script_xref(name : "URL" , value : "http://dev.gentoo.org/~rbu/security/debiantemp/openoffice.org-common");

  script_description(desc);
  script_summary("Check for the version of OpenOffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

filePath = find_file(file_name:"versionrc", sock:sock);
foreach path (filePath)
{
  path = chomp(path);
  if("openoffice" >!< path){
    continue;
  }

  openoffVer = get_bin_version(full_prog_name:"cat", version_argv:path,
                               ver_pattern:"[0-9]\.[0-9](\.[0-9])?");
  if(openoffVer != NULL)
  {
    if(openoffVer[0] == "2.4.1"){
      security_hole(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
