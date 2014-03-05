###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xymon_monitor_unspecified_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Xymon Monitor Unspecified Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.
  Impact Level: Application";
tag_affected = "Xymon Monitor versions 4.3.0 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input by
  multiple unspecified scripts which allows attackers to execute arbitrary
  HTML and script code on the web server.";
tag_solution = "Upgrade to Xymon Monitor version 4.3.1 or later,
  For updates refer to http://xymon.sourceforge.net/";
tag_summary = "This host is running Xymon Monitor and is prone to unspecified
  multiple cross site scripting vulnerabilities.";

if(description)
{
  script_id(902504);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_cve_id("CVE-2011-1716");
  script_bugtraq_id(47156);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Xymon Monitor Unspecified Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/71489");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44036");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66542");
  script_xref(name : "URL" , value : "http://xymon.svn.sourceforge.net/viewvc/xymon/branches/4.3.2/Changes?revision=6673&amp;view=markup");

  script_description(desc);
  script_summary("Check for the version of Xymon Monitor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_xymon_monitor_detect.nasl");
  script_require_ports("Services/www", 80);
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

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Check for Xymon Monitor versions 4.3.0 and prior.
if(vers = get_version_from_kb(port:port,app:"Xymon"))
{
  if(version_is_less_equal(version:vers, test_version:"4.3.0")){
    security_warning(port:port);
  }
}
