##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_mult_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Limny Multiple Cross-site Request Forgery (CSRF) Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to change the administrative
  password or email address and add a new user by tricking an administrative user
  into visiting a malicious web site.
  Impact Level: Application.";
tag_affected = "Limny version 2.0";

tag_insight = "The multiple flaws are caused by improper validation of user-supplied input,
  which allows users to perform certain actions via HTTP requests without
  performing any validity checks to verify the requests.";
tag_solution = "Upgrade to Limny version 2.01
  For updates refer to http://www.limny.org/";
tag_summary = "This host is running Limny is prone to multiple cross-site request
  forgery vulnerabilities";

if(description)
{
  script_id(800296);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0709");
  script_name("Limny Multiple Cross-site Request Forgery (CSRF) Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38616");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56318");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11478");

  script_description(desc);
  script_summary("Check for the version of Limny");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_limny_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");
include("http_func.inc");

limPort = get_http_port(default:80);
if(!limPort){
  exit(0);
}

limVer = get_kb_item("www/" + limPort + "/Limny");
if(!limVer){
  exit(0);
}

limVer= eregmatch(pattern:"^(.+) under (/.*)$", string:limVer);
if(limVer[1] != NULL)
{
  if(version_is_less_equal(version:limVer[1], test_version:"2.0")){
    security_hole(limPort);
  }
}
