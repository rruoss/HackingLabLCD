###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kodak_insite_multiple_xss.nasl 13 2013-10-27 12:16:33Z jan $
#
# Kodak InSite Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This
  may allow the attacker to steal cookie-based authentication credentials and to
  launch other attacks.
  Impact Level: Application";
tag_affected = "Kodak InSite version 6.0.x and prior.";
tag_insight = "Multiple flaws are due to input validation error in 'Language'
  parameter to Pages/login.aspx, 'HeaderWarning' parameter to Troubleshooting
  /DiagnosticReport.asp and 'User-Agent' header to troubleshooting/speedtest.asp,
  which allows remote attackers to inject arbitrary web script or HTML.";
tag_solution = "No solution or patch is available as of 17th March, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://graphics.kodak.com/US/en/Product/workflow_data_storage/Production/Portal_Products/INSITE_Prepress_Portal/default.htm";
tag_summary = "This host is running Kodak InSite and is prone to multiple cross-site scripting
  vulnerabilities.";

if(description)
{
  script_id(801909);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_cve_id("CVE-2011-1427");
  script_bugtraq_id(46762);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Kodak InSite Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/Mar/73");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65941");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516880");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/516880/100/0/threaded");

  script_description(desc);
  script_summary("Check for Kodak InSite Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
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

##
## The script code starts here
##

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

sndReq = http_get(item:string("/Site/Pages/login.aspx"), port:port);
rcvRes = http_keepalive_send_recv(port:port,data:sndReq);

## Confirm the Application
if("InSite" >< rcvRes && "PoweredByKodak" >< rcvRes)
{
   ## Path of Vulnerable Page
   url = "/Pages/login.aspx?SessionTimeout=False&Language=de%26rflp=True','" + 
         "00000000-0000-0000-0000-000000000000');alert('XSS!-TEST'); return fal" +
         "se; a('";

   ## Try attack and check the response to confirm vulnerability.
   if(http_vuln_check(port:port, url:url, pattern:");alert\('XSS!-TEST'\);")){
     security_warning(port);
   }
}
