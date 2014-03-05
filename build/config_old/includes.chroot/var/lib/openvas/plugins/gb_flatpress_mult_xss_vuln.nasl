###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flatpress_mult_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# FlatPress Multiple Cross site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will let the remote attacker to execute arbitrary web
  script or HTML code in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "FlatPress version 0.909 and prior.";
tag_insight = "The flaws are due to error in 'contact.php','login.php' and
  'search.php' that fail to sufficiently sanitize user-supplied data via the
  PATH_INFO.";
tag_solution = "No solution or patch is available as of 21th January, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/flatpress/files/";
tag_summary = "This host is running FlatPress and is prone to multiple Cross Site
  Scripting vulnerabilities.";

if(description)
{
  script_id(800284);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4461");
  script_bugtraq_id(37471);
  script_name("FlatPress Multiple Cross site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37938");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10688");

  script_description(desc);
  script_summary("Check for the version of FlatPress");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("flatpress_detect.nasl");
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


include("version_func.inc");
include("http_func.inc");

fpPort = get_http_port(default:80);
if(!fpPort){
  exit(0);
}

flatVer = get_kb_item("www/" + fpPort + "/flatpress");
if(!flatVer){
  exit(0);
}

flatVer = eregmatch(pattern:"^(.+) under (/.*)$", string:flatVer);
if(!safe_checks() && flatVer[2] != NULL)
{
  sndReq = http_get(item:string(flatVer[2], "/contact.php/>'><ScRiPt>" +
                         "alert('+213567778899')</ScRiPt>"), port:fpPort);
  rcvRes = http_send_recv(port:fpPort, data:sndReq);
  if(!isnull(rcvRes) && ("213567778899" >< rcvRes))
  {
    security_warning(fpPort);
    exit(0);
  }
}

if(flatVer[1] != NULL)
{
  if(version_is_less_equal(version:flatVer[1], test_version:"0.909")){
    security_warning(fpPort);
  }
}
