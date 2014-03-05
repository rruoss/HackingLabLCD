###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ikiwiki_htmlscrubber_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ikiwiki 'htmlscrubber' Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary script code,
  in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "ikiwiki versions 2.x through 2.53.4 and 3.x through 3.20100311";
tag_insight = "The flaw is caused by an input validation error in the htmlscrubber component
  when processing 'data:image/svg+xml' URIs.";
tag_solution = "Upgrade to ikiwiki version 2.53.5 or 3.20100312
  http://ikiwiki.info/download/";
tag_summary = "This host is installed Ikiwiki and is prone to Cross Site
  Scripting vulnerability.";

if(description)
{
  script_id(800746);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-1195");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Ikiwiki 'htmlscrubber' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38983");
  script_xref(name : "URL" , value : "http://ikiwiki.info/security/#index36h2");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0662");

  script_description(desc);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Ikiwiki");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_ikiwiki_detect.nasl");
  script_require_keys("ikiwiki/Ver");
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

ikiwikiVer = get_kb_item("ikiwiki/Ver");
if(ikiwikiVer != NULL)
{
  if(version_in_range(version:ikiwikiVer, test_version:"2.0", test_version2:"2.53.4")||
     version_in_range(version:ikiwikiVer, test_version:"3.0", test_version2:"3.20100311")){
      security_warning(0);
  }
}
