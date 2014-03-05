##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_n_13_news_csrf_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# N-13 News Cross-Site Request Forgery Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary script
  code, perform cross-site scripting attacks, Web cache poisoning, and other
  malicious activities.
  Impact Level: Application.";
tag_affected = "N-13 News version 3.4, 3.7 and 4.0";
tag_insight = "The flaw is caused by an improper validation of user-supplied input by the
  'admin.php' script, which allows remote attackers to send a specially
  crafted HTTP request to add an administrative user.";
tag_solution = "No solution or patch is available as of 08th February, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://code.google.com/p/n-13news/";
tag_summary = "This host is running N-13 News and is prone to Cross-Site Request
  Forgery vulnerability.";

if(description)
{
  script_id(801738);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_cve_id("CVE-2011-0642");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("N-13 News Cross-Site Request Forgery Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42959");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64824");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16013/");

  script_description(desc);
  script_summary("Check for version the of N-13 News");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_n_13_news_detect.nasl");
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
include("http_keepalive.inc");

## Get HTTP Port
newsPort = get_http_port(default:80);
if(!newsPort){
  exit(0);
}

## Get version from KB
newsVer = get_version_from_kb(port:newsPort, app:"N-13/News");
if(newsVer)
{
  if(version_is_equal(version:newsVer, test_version:"3.4") ||
     version_is_equal(version:newsVer, test_version:"3.7") ||
     version_is_equal(version:newsVer, test_version:"4.0")){
       security_warning(newsPort);
  }
}
