###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_unspecified_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# HP System Management Homepage Unspecified XSS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to steal cookie-based
  authentication credentials and execute arbitrary script on the user's
  web browser by injecting web script or HTML vi remote vectors.";
tag_affected = "HP System Management Homepage versions prior to 3.0.1.73 on all platforms.";
tag_insight = "HP System Management Homepage application fails to validate user supplied
  input.";
tag_solution = "Upgrade to version 3.0.1.73 or later,
  http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01745065";
tag_summary = "This host is running HP System Management Homepage (SMH) and is
  prone to cross-site scripting vulnerability.";

if(description)
{
  script_id(900658);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(35031);
  script_cve_id("CVE-2009-1418");
  script_name("HP System Management Homepage Unspecified XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50633");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2009/JVNDB-2009-000029.html");

  script_description(desc);
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 SecPod");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_require_ports("Services/www", 2301);
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

smhPort = get_http_port(default:2301);
if(!get_port_state(smhPort)){
  exit(0);
}

smhVer = get_kb_item("www/" + smhPort+ "/HP/SMH");
if(smhVer != NULL)
{
  if(version_is_less(version:smhVer, test_version:"3.0.1.73")){
    security_warning(smhPort);
  }
}
