###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_freeway_php_info_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Freeway '.php' Files Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to gain sensitive information.
  Impact Level: Application";
tag_affected = "Freeway version 1.5 Alpha.";
tag_insight = "The flaw is due to error in certain '.php' files. A direct request
  to these files reveals the installation path in an error message.";
tag_solution = "No solution or patch is available as of 27th September 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.openfreeway.org";
tag_summary = "The host is running Freeway and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(902737);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_cve_id("CVE-2011-3739");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Freeway '.php' Files Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2011-3739");
  script_xref(name : "URL" , value : "http://yehg.net/lab/pr0js/advisories/path_disclosure/freeway_1_5_alpha_Burstow");
  script_xref(name : "URL" , value : "http://securityswebblog.blogspot.com/2011/09/vulnerability-summary-for-cve-2011-3739_26.html");

  script_description(desc);
  script_summary("Check Freeway is prone to information disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Get the HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list("/freeway", "", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/admin/login.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Conform the application
  if("<title>Freeway</title>" >< rcvRes)
  {
    ## Construct the Attack Request
    url = dir + "/templates/Freeway/boxes/last_product.php";

    ## Try attack and check the installation path in response.
    if(http_vuln_check(port:port, url:url, pattern:"<b>Parse error</b>:  " +
       "syntax error, unexpected .*templates/Freeway/boxes/last_product.php"))
    {
      security_warning(port:port);
      exit(0);
    }
  }
}