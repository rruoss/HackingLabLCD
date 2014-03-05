###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_xss_filter_xss_vuln_nov09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Internet Explorer 'XSS Filter' XSS Vulnerabilities - Nov09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to conduct cross-site scripting
  attacks on the affected system.
  Impact Level: System";
tag_affected = "Microsoft Internet Explorer version 8 on Windows.";
tag_insight = "The XSS Filter used in 'response-changing mechanism' to conduct XSS attacks
  against web sites that have no inherent XSS vulnerabilities, related to the
  details of output encoding.";
tag_solution = "No solution or patch is available as of 27th November, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "This host is installed with Internet Explorer and is prone to
  Cross-Site Scripting vulnerability.

  This NVT has been replaced by NVT secpod_ms10-002.nasl
  (OID:1.3.6.1.4.1.25623.1.0.901097).";

if(description)
{
  script_id(900898);
  script_version("$Revision: 15 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4074");
  script_bugtraq_id(37135);
  script_name("Microsoft Internet Explorer 'XSS Filter' XSS Vulnerabilities - Nov09");
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
  script_xref(name : "URL" , value : "http://www.owasp.org/images/5/50/OWASP-Italy_Day_IV_Maone.pdf");
  script_xref(name : "URL" , value : "http://www.theregister.co.uk/2009/11/20/internet_explorer_security_flaw/");
  script_xref(name : "URL" , value : "http://hackademix.net/2009/11/21/ies-xss-filter-creates-xss-vulnerabilities/");

  script_description(desc);
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


exit(66); ## This NVT is deprecated as addressed in secpod_ms10-002.nasl

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for MS IE version 8
if(ieVer =~ "^8\..*"){
  security_warning(0);
}
