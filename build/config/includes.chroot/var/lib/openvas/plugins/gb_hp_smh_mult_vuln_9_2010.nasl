###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_mult_vuln_9_2010.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP System Management Homepage Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "HP System Management Homepage is prone to multiple Vulnerabilities.

1. An HTTP response-splitting vulnerability.

Attackers can leverage this issue to influence or misrepresent how web
content is served, cached, or interpreted. This could aid in various
attacks that try to entice client users into a false sense of trust.

2. An unspecified remote information-disclosure vulnerability.

Remote attackers can exploit this issue to obtain sensitive
information that may lead to further attacks. 

HP System Management Homepage versions prior to 6.2 are vulnerable.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_id(100810);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
 script_bugtraq_id(43269,43208);
 script_cve_id("CVE-2010-3011","CVE-2010-3009", "CVE-2010-3012");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

 script_name("HP System Management Homepage Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43269");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43208");
 script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02512995&amp;admit=109447626+1284637282234+28353475");
 script_xref(name : "URL" , value : "https://www.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02475053");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed HP System Management Homepage is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 2301,2381);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:2381);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "HP System Management Homepage" >!< banner)exit(0);

version = eregmatch(pattern:"Server:.*HP System Management Homepage/([0-9._]+)", string:banner);
if(isnull(version[1]))exit(0);

vers = version[1];

if(!isnull(vers)) {

  if(version_is_less(version: vers, test_version: "6.2.0.12")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);

