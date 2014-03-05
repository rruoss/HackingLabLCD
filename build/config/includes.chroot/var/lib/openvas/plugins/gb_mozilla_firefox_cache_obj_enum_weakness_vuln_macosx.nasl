###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_cache_obj_enum_weakness_vuln_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mozilla Firefox Cache Objects History Enumeration Weakness Vulnerability (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to extraction browser
  history by observing cache timing via crafted JavaScript code.
  Impact Level: Application";
tag_affected = "Mozilla Firefox versions 8.0.1 and prior on MAC OS X";
tag_insight = "The flaw is caused due an error in handling cache objects and can be
  exploited to enumerate visited sites.";
tag_solution = "No solution or patch is available as of 09th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to cache
  objects history enumeration weakness vulnerability.";

if(description)
{
  script_id(802548);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4688");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-09 17:53:11 +0530 (Fri, 09 Dec 2011)");
  script_name("Mozilla Firefox Cache Objects History Enumeration Weakness Vulnerability (MAC OS X)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47090");
  script_xref(name : "URL" , value : "http://lcamtuf.coredump.cx/cachetime/");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_require_keys("Mozilla/Firefox/MacOSX/Version");
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

## Firefox Check
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  ## Grep for Firefox versions before 8.0.1
  if(version_is_less_equal(version:ffVer, test_version:"8.0.1")){
    security_warning(0);
  }
}
