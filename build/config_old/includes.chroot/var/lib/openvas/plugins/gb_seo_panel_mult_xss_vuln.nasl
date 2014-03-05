##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seo_panel_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Seo Panel Multiple Cross-site Scripting (XSS) Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site and potentially allowing the attacker to steal cookie-based
  authentication credentials or to control how the site is rendered to the
  user.
  Impact Level: Application";
tag_affected = "Seo Panel version 2.2.0";

tag_insight = "The flaws are caused by improper validation of user-supplied input by the
  'index.ctrl.php' or 'controllers/settings.ctrl.php' scripts. A remote attacker
  could exploit this vulnerability using the default_news or sponsors parameter
  to inject malicious script into a Web page.";
tag_solution = "No solution or patch is available as of 18th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/seopanel/files/";
tag_summary = "This host is running Seo Panel and is prone to multiple Cross-site
  scripting vulnerabilities.";

if(description)
{
  script_id(801775);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-26 15:24:49 +0200 (Tue, 26 Apr 2011)");
  script_cve_id("CVE-2010-4331");
  script_bugtraq_id(45828);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Seo Panel Multiple Cross-site Scripting (XSS) Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64725");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16000/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/515768/100/0/threaded");

  script_description(desc);
  script_summary("Check if Seo Panel is vulnerable to XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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
include("http_keepalive.inc");

spPort = get_http_port(default:80);
if(!get_port_state(spPort)){
  exit(0);
}

foreach dir (make_list("/seopanel", "/SeoPanel", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/"), port:spPort);
  rcvRes = http_keepalive_send_recv(port:spPort, data:sndReq);

  ## Confirm the application
  if('<title>Seo Panel' >< rcvRes)
  {
    ## Construct request
    sndReq = string("GET ", dir, "/index.php?sec=news"," HTTP/1.1\r\n",
                    "Host: ", get_host_name(), "\r\n",
                    "Cookie: default_news=<script>alert('XSS-TEST')</script>", "\r\n\r\n");
    rcvRes = http_keepalive_send_recv(port:spPort, data:sndReq);

    ## Check the Response to confirm vulnerability
    if("<script>alert('XSS-TEST')</script>" >< rcvRes){
      security_warning(spPort);
    }
  }
}
