###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ffftp_list_cmd_dir_traversal_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# FFFTP LIST Command Directory Traversal Vulnerability.
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to create or overwrite
  arbitrary files on a vulnerable system by tricking a user into downloading
  a directory containing files.
  Impact Level: System";
tag_affected = "FFFTP version 1.96b and prior on Windows.";
tag_insight = "The flaw is due to input validation error when processing FTP
  responses to a LIST command with a filename and is followed by ../ (dot dot
  forward-slash).";
tag_solution = "Upgrade to version 1.96d or later from,
  http://www2.biglobe.ne.jp/~sota/ffftp-e.html";
tag_summary = "This host is installed with FFFTP Client and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(800533);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6424");
  script_bugtraq_id(29459);
  script_name("FFFTP LIST Command Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30428/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/1708/references");

  script_description(desc);
  script_summary("Check for the Version of FFFTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_ffftp_detect.nasl");
  script_require_keys("FFFTP/Ver");
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

ffftpVer = get_kb_item("FFFTP/Ver");
if(!ffftpVer){
  exit(0);
}

# Check for FFFTP Version 1.96b (1.96.2.0)
if(version_is_less_equal(version:ffftpVer, test_version:"1.96.2.0")){
  security_hole(0);
}
