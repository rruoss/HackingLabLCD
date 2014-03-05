###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_woltlab_burning_board_csrf_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# WoltLab Burning Board Cross-Site Request Forgery Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Attackers can exploit this issue to delete private messages by sending
  malicious input in the 'pmID' parameter in a delete action in a PM page.
  Impact Level: Application";
tag_affected = "WoltLab Burning Board version 3.x";
tag_insight = "An error arises in index.php due to improper sanitization of user-supplied
  input which may allows remote attackers to hijack the users authentication.";
tag_solution = "No solution or patch is available as of 14th September 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.woltlab.com/products/burning_board/index_en.php";
tag_summary = "This host is running WoltLab Burning Board and is prone to
  Cross-Site Request Forgery vulnerability.";

if(description)
{
  script_id(900937);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-7192");
  script_name("WoltLab Burning Board Cross-Site Request Forgery Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/39990");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/487139/100/200/threaded");

  script_description(desc);
  script_summary("Check for the version of WoltLab Burning Board");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_woltlab_burning_board_detect.nasl");
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

wbbPort = get_http_port(default:80);
if(!wbbPort)
{
  exit(0);
}

wbbVer = get_kb_item("www/" + wbbPort + "/BurningBoard");
wbbVer = eregmatch(pattern:"^(.+) under (/.*)$", string:wbbVer);

if(wbbVer[1] =~ "^3\..*"){
  security_hole(wbbPort);
}
