###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_robo_ftp_client_dir_trav_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Robo-FTP Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to download or upload arbitrary
  files. This may aid in further attacks.
  Impact Level: Application";
tag_affected = "Robo-FTP versions prior to 3.7.5.";
tag_insight = "This flaw is due to an input validation error when downloading
  directories containing files with directory traversal specifiers in the
  filename. This can be exploited to download files to an arbitrary location
  on a user's system.";
tag_solution = "Upgrade to Robo-FTP version 3.7.5 or later,
  For updates refer to http://www.robo-ftp.com/download/";
tag_summary = "This host is installed with Robo-FTP and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(801626);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)");
  script_bugtraq_id(44073);
  script_cve_id("CVE-2010-4095");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Robo-FTP Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41809");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62548");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/directory_traversal_vulnerability_in_robo_ftp.html");

  script_description(desc);
  script_summary("Check for the version of Robo-FTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_robo_ftp_client_detect.nasl");
  script_require_keys("Robo/FTP/Ver");
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

## Get version from KB
roboVer = get_kb_item("Robo/FTP/Ver");

if(roboVer != NULL)
{
  ## Grep for Robo-FTP versions prior to 3.7.5
  if(version_is_less(version:roboVer, test_version:"3.7.5") ){
    security_hole(0);
  }
}
