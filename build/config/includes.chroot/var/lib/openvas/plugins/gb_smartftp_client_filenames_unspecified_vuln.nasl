###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smartftp_client_filenames_unspecified_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SmartFTP Filename Processing Unspecified Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Has an unknown impact and attack vector.
  Impact Level: Application";
tag_affected = "SmartFTP Client version prior to 4.0.1142.0";

tag_insight = "An unspecified flaw exists in SmartFTP when processing filenames, has an
  unknown impact and attack vector.";
tag_solution = "Update SmartFTP Client to version 4.0 Build 1142 or later.
  For updates refer to http://www.smartftp.com/download/";
tag_summary = "This host is installed with SmartFTP Client and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(801992);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2010-4871");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("SmartFTP Filename Processing Unspecified Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42060");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/63113");
  script_xref(name : "URL" , value : "https://www.smartftp.com/forums/index.php?/topic/16425-smartftp-client-40-change-log/");

  script_description(desc);
  script_summary("Check for the version of SmartFTP Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_smartftp_client_detect.nasl");
  script_require_keys("SmartFTP/Client/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);

}


include("version_func.inc");

sftpVer = get_kb_item("SmartFTP/Client/Ver");
if(sftpVer != NULL)
{
  # Check for SmartFTP < 4.0.1142.0
  if(version_is_less(version:sftpVer, test_version:"4.0.1142.0")){
    security_hole(0);
  }
}
