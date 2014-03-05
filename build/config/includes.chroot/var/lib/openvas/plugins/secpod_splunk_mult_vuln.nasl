###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_splunk_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Splunk Multiple vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to obtain sensitive information
  and gain privileges.
  Impact Level: Application";
tag_affected = "Splunk version 4.0.0 through 4.1.4";
tag_insight = "- XML parser is vulnerable to XXE (XML eXternal Entity) attacks,
    which allows remote authenticated users to obtain sensitive information
    and gain privileges.
  - SPLUNKD_SESSION_KEY parameter is vulnerable to session hijacking.";
tag_solution = "Upgrade to Splunk version 4.1.5 or later,
  For updates refer to http://www.splunk.com/download";
tag_summary = "This host is running Splunk and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(901152);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3322", "CVE-2010-3323");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Splunk Multiple vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.splunk.com/view/SP-CAAAFQ6");

  script_description(desc);
  script_summary("Determine if running Splunk version is vulnerable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_require_ports("Services/www", 8000);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get Splunk Port
port = get_http_port(default:8000);
if(!get_port_state(port)) {
  exit(0);
}

## Get Splunk Version from KB
vers = get_kb_item(string("www/", port, "/splunk"));
if(!isnull(vers))
{
  ## Check for Splunk Versions 4.0.0 through 4.1.4
  if(version_in_range(version: vers, test_version: "4.0", test_version2:"4.1.4")){
    security_hole(port:port);
  }
}
