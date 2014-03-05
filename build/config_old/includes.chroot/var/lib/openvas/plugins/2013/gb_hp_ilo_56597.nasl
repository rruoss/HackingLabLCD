###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_ilo_56597.nasl 52 2013-11-08 18:43:19Z mime $
#
# HP Integrated Lights-Out Unspecified Information Disclosure Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103783";
CPE = "cpe:/o:hp:integrated_lights-out";

tag_insight = "Allows remote attackers to obtain sensitive information via unknown vectors.";

tag_impact = "Remote attackers can exploit this issue to gain access to sensitive
information that may aid in further attacks.";

tag_affected = "Integrated Lights-Out 3 (aka iLO3) with firmware before 1.50 and
Integrated Lights-Out 4 (aka iLO4) with firmware before 1.13";

tag_summary = "HP Integrated Lights-Out is prone to an unspecified information-
disclosure vulnerability.";

tag_solution = "Updates are available.";
tag_vuldetect = "Check the firmware version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56597);
 script_cve_id("CVE-2012-3271");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 52 $");

 script_name("HP Integrated Lights-Out Unspecified Information Disclosure Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56597");
 script_xref(name:"URL", value:"http://www.hp.com");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-11-08 19:43:19 +0100 (Fr, 08. Nov 2013) $");
 script_tag(name:"creation_date", value:"2013-09-10 18:14:19 +0200 (Tue, 10 Sep 2013)");
 script_description(desc);
 script_summary("Check the firmware version");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("ilo_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("HP_ILO/installed");

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
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(fw_vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(!ilo_vers = get_kb_item('www/' + port + '/HP_ILO/ilo_version'))exit(0);

  if(int(ilo_vers) == 3)      t_vers = '1.50';
  else if(int(ilo_vers) == 4) t_vers = '1.13';

  if(version_is_less(version:fw_vers, test_version:t_vers)) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);