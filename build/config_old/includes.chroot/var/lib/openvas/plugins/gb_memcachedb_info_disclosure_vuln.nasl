###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_memcachedb_info_disclosure_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MemcacheDB Information Disclosure Vulnerability
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
tag_solution = "No solution or patch is available as of 18th May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://memcachedb.org

  Workaround:
  Apply the workaround.
  http://www.positronsecurity.com/advisories/2009-001.html";

tag_impact = "Successful exploitation will let the attacker craft execute malicious commands
  and pass it to the vulnerable functions to gain sensitive information about the
  application.";
tag_affected = "MemcacheDB version 1.2.0 and prior";
tag_insight = "Error in process_stat function discloses the contents of /proc/self/maps in
  response to a stats maps command.";
tag_summary = "The host is running MemcacheDB and is prone to Information Disclosure
  Vulnerabilities.";

if(description)
{
  script_id(800717);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1255");
  script_bugtraq_id(34756);
  script_name("MemcacheDB Information Disclosure Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/34932");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1197");

  script_description(desc);
  script_summary("Check for the version of MemcacheDB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_memcachedb_detect.nasl");
  script_require_keys("MemCacheDB/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

memcachedbVer = get_kb_item("MemCacheDB/Ver");
if(memcachedbVer == NULL){
  exit(0);
}

# Grep for MemcacheDB version 1.2.0 and prior
if(version_is_less_equal(version:memcachedbVer, test_version:"1.2.0")){
  security_warning(memdbPort);
}
