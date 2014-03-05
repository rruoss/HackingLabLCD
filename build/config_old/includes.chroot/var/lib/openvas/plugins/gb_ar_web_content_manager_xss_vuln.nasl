###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ar_web_content_manager_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# AR Web Content Manager (AWCM) 'search.php' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary HTML
  code in a user's browser session in the context of a vulnerable application.
  Impact Level: Application.";
tag_affected = "AWCM CMS version 2.2 and prior";
tag_insight = "Input passed via the 'search' parameter in 'search' action in search.php is not
  properly verified before it is returned to the user. This can be exploited
  to execute arbitrary HTML and script code in a user's browser session in the
  context of a vulnerable site. This may allow an attacker to steal cookie-based
  authentication credentials and launch further attacks.";
tag_solution = "Apply the patch from below link,
  For updates refer to http://www.zshare.net/download/8818096688e1e96a/";
tag_summary = "The host is running AR Web Content Manager (AWCM) and is prone to Cross-Site
  Scripting vulnerability.";

if(description)
{
  script_id(801911);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2011-1668");
  script_bugtraq_id(47126);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("AR Web Content Manager (AWCM) 'search.php' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=179");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/47126/");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_AWCM_XSS.txt");

  script_description(desc);
  script_summary("Check for the Cross-Site Scripting vulnerability in AWCM CMS ");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks");
  script_family("Web application abuses");
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

awcmPort = get_http_port(default:80);
if(!awcmPort){
  exit(0);
}

foreach dir (make_list("/awcm", "/AWCM", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:awcmPort);
  rcvRes = http_send_recv(port:awcmPort, data:sndReq);

  ## Confirm the application
  if(">AWCM" >< rcvRes)
  {
    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:awcmPort, url:dir + '/search.php?search=<script>' +
                       'alert("XSS-Test")</script>&where=all',
                       pattern:'(<script>alert."XSS-Test".</script>)'))
    {
      security_warning(port:awcmPort);
      exit(0);
    }
  }
}
