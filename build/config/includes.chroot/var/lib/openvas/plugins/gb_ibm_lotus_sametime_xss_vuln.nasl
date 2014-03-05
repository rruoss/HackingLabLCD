###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_sametime_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Lotus Sametime Server 'stcenter.nsf' Cross Site Scripting Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.
  Impact Level: Application.";
tag_affected = "IBM Lotus Sametime version 8.0 and 8.0.1";
tag_insight = "Input passed to the 'authReasonCode' parameter in 'stcenter.nsf' when
  'OpenDatabase' is set, is not properly sanitised before being returned to
  the user.";
tag_solution = "No solution or patch is available as of 03rd March, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www-01.ibm.com/software/lotus/sametime/";
tag_summary = "The host is running IBM Lotus Sametime Server and is prone to cross
  site scripting vulnerability";

if(description)
{
  script_id(801901);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1106");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IBM Lotus Sametime Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43430/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65555");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/46481.txt");

  script_description(desc);
  script_summary("Determine if Lotus Sametime Server is prone to a cross-site scripting vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
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
include("global_settings.inc");

port = get_http_port(default:80);

## Check for the default port
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application from banner
banner = get_http_banner(port:port);
if(!banner || "Server: Lotus-Domino" >!< banner){
  exit(0);
}

## Construct the attack string
url = string("/stcenter.nsf?OpenDatabase&authReasonCode=" +
             "'><script>alert('XSS-TEST');</script>'");

## Confirm the exploit
if(http_vuln_check(port:port, url:url,
   pattern:"<script>alert\('XSS-TEST'\)</script>")){
  security_warning(port:port);
}
