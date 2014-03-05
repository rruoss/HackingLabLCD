###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rt_unspecified_dir_traversal_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# RT (Request Tracker) Unspecified Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to access and disclose files
  outside of RT's root directory via directory traversal attacks.
  Impact Level: Application";
tag_affected = "RT (Request Tracker) versions 3.2.0 through 3.6.10, 3.8.0 through 3.8.9,
  and 4.0.0rc through 4.0.0rc7";
tag_insight = "The flaw is caused by an unspecified input validation error and can be
  exploited to access and disclose files outside of RT's root directory via
  directory traversal attacks.";
tag_solution = "Upgrade to RT (Request Tracker) version 3.8.10, 3.6.11 or 4.0.0rc8.
  For updates refer to http://www.bestpractical.com/rt/";
tag_summary = "This host is installed with Request Tracker and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(902511);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_cve_id("CVE-2011-1688");
  script_bugtraq_id(47383);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("RT (Request Tracker) Unspecified Directory Traversal Vulnerability");
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
  script_summary("Check for the version of Request Tracker");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("rt_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44189");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66795");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=696795");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

## Check for vulnerable RT versions
if(vers = get_version_from_kb(port:port,app:"rt_tracker"))
{
  if(version_in_range(version:vers, test_version:"3.8.0", test_version2:"3.8.9") ||
     version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.6.10")||
     version_in_range(version:vers, test_version:"4.0.0.rc1", test_version2:"4.0.0.rc7")){
    security_warning(port:port);
  }
}
