##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tribisur_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Tribisur Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  and execute arbitrary local scripts in the context of an affected site.
  Impact Level: Application.";
tag_affected = "Tribisur version 2.1 and prior.";

tag_insight = "Multiple flaws are due to:
  - An input passed to the 'theme' parameter in 'modules/hayoo/index.php' is not
    properly verified before being used to include files.
  - An Input passed to the 'id' parameter in 'cat_main.php', and other parameters
    is not properly sanitised before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 18th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.comscripts.com/scripts/php.tribisur-20.1211.html";
tag_summary = "This host is running Tribisur and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(800740);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0958");
  script_bugtraq_id(38596);
  script_name("Tribisur Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28362");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11655");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1003-exploits/tribisur-lfi.txt");

  script_description(desc);
  script_summary("Check for the version of Tribisur");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

triPort = get_http_port(default:80);
if(!triPort){
  exit(0);
}

if(!get_port_state(triPort)){
  exit(0);
}

foreach dir (make_list("/Tribisur", "/tribisur", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/scripts.php"), port:triPort);
  rcvRes = http_send_recv(port:triPort, data:sndReq);
  if("TRIBISUR" >< rcvRes)
  {
    triVer = eregmatch(pattern:" //v([0-9.]+)", string:rcvRes);
    if(triVer[1] != NULL)
    {
      if(version_is_less_equal(version:triVer[1], test_version:"2.1")){
        security_hole(triPort);
      }
    }
  }
}
