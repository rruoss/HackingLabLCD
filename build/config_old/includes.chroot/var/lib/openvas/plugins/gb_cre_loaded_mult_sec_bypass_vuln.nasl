###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cre_loaded_mult_sec_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CRE Loaded Multiple Security Bypass Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to bypass authentication and
  gain administrator privileges.
  Impact Level: Application";
tag_affected = "CRE Loaded version before 6.4.0";
tag_insight = "The flaws are due to
  - An error when handling 'PHP_SELF' variable, by includes/application_top.php
    and admin/includes/application_top.php.
  - Request, with 'login.php' or 'password_forgotten.php' appended as the
    'PATH_INFO', which bypasses a check that uses 'PHP_SELF', which is not
    properly handled by includes/application_top.php and
    admin/includes/application_top.php.";
tag_solution = "Upgrade to CRE Loaded version 6.4.0 or later
  For updates refer to http://www.creloaded.com/";
tag_summary = "The host is running CRE Loaded and is prone to Security bypass
  vulnerability.";

if(description)
{
  script_id(802104);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_cve_id("CVE-2009-5076", "CVE-2009-5077");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("CRE Loaded Multiple Security Bypass Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://hosting-4-creloaded.com/node/116");
  script_xref(name : "URL" , value : "https://www.creloaded.com/fdm_file_detail.php?file_id=191");

  script_description(desc);
  script_summary("Check the version of CRE Loaded");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir(make_list("/cre", "/cre-loaded", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get (item: string (dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('<title>CRE Loaded' >< res)
  {
    ## Get the version
    ver = eregmatch(pattern:"v([0-9.]+)" , string:res);
    if (ver != NULL)
    {
      ## Check the version less than 6.4.0
      if(version_is_less(version:ver, test_version:"6.4.0")){
        security_hole(port);
      }
    }
  }
}
