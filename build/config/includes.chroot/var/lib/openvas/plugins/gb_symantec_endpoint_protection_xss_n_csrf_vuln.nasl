###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_endpoint_protection_xss_n_csrf_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Symantec Endpoint Protection Manager XSS and CSRF Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site.
  Impact Level: Application";
tag_affected = "Symantec Endpoint Protection (SEP) version 11.0.600x through 11.0.6300";
tag_insight = "Multiple flaws are due to
  - Input appended to the URL after /console/apps/sepm is not properly
    sanitised before being returned to the user.
  - Input passed via the 'token' parameter to portal/Help.jsp is not properly
    sanitised before being returned to the user.
  - The portal application allows users to perform certain actions via HTTP
    requests without performing any validity checks to verify the requests.";
tag_solution = "Upgrade to Symantec Endpoint Protection (SEP) version 11.0.7000 RU7 or
  later,For updates refer to http://www.symantec.com/business/endpoint-protection";
tag_summary = "This host is installed with Symantec Endpoint Protection Manager
  and is prone to cross site scripting and cross site request forgery
  vulnerabilities.";

if(description)
{
  script_id(802242);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2011-0550", "CVE-2011-0551");
  script_bugtraq_id(48231, 49101);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Symantec Endpoint Protection Manager XSS and CSRF Vulnerabilities");
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


  script_description(desc);
  script_summary("Check for the version of Symantec Endpoint Protection Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_require_keys("Symantec/Endpoint/Protection");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43662");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1025919");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69136");
  script_xref(name : "URL" , value : "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=2011&amp;suid=20110810_00");
  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("Symantec/Endpoint/Protection");
if(version)
{
  ## Check for Symantec Endpoint Protection version 11.0.600x through 11.0.6300.
  if(version_in_range(version:version, test_version:"11.0.600", test_version2:"11.0.6300")){
    security_hole(0);
  }
}
