##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_fusion_catid_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# PHP-Fusion 'cat-id' Cross Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed.
  Impact Level: Application";
tag_affected = "PHP-Fusion version 7.02.04";


tag_insight = "The flaw is due to input passed via the 'cat_id' parameter to
  'downloads.php' is not properly sanitized before being it is
  returned to the user.";
tag_solution = "Apply the patch or upgrade to 7.02.05 or later,
  For updates refer to http://www.php-fusion.co.uk/index.php";
tag_summary = "This host is installed with PHP-Fusion and is prone cross site
  scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803221";
CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6043");
  script_bugtraq_id(51365);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-01 10:26:58 +0530 (Fri, 01 Feb 2013)");
  script_name("PHP-Fusion 'cat-id' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51365/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/108542/phpfusion70204-xss.txt");

  script_description(desc);
  script_summary("Check if PHP-Fusion is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_require_keys("phpfusion/installed");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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
include("host_details.inc");

## Get HTTP Port
if(!pfPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:pfPort)){
  exit(0);
}

## Get PHP-Fusion Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:pfPort))exit(0);

## Construct XSS attack request
url = dir + '/downloads.php?cat_id="<script>alert(document.cookie)</script>';

## Confirm exploit worked properly or not
if(http_vuln_check(port:pfPort, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>"))
{
  security_warning(pfPort);
  exit(0);
}
