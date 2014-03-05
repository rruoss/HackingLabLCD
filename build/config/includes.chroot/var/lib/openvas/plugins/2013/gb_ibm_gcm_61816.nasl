###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_gcm_61816.nasl 11 2013-10-27 10:12:02Z jan $
#
# IBM 1754 GCM16 and GCM32 Global Console Managers Multiple Command Execution Vulnerabilities
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
tag_impact = "Successful exploit of these issues may allow an attacker to execute
arbitrary commands with the privileges of the root user.
Impact Level: System";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103768";

tag_insight = "IBM 1754 GCM16 and GCM32 versions 1.18.0.22011 and below contain a flaw
that allows a remote authenticated user to execute unauthorized commands as
root. This flaw exist because webapp variables are not sanitized.";


tag_affected = "IBM 1754 GCM16 Global Console Manager 1.18.0.22011 and prior
IBM 1754 GCM32 Global Console Manager 1.18.0.22011 and prior ";

tag_summary = "IBM 1754 GCM16 and GCM32 Global Console Managers are prone to multiple
command-execution vulnerabilities because they fail to sanitize user-supplied input.";

tag_solution = "Updates (Version 1.18.0.22011) are available.";

tag_vuldetect = "Check if the firmware version is greater than 1.18.0.22011";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61816);
 script_cve_id("CVE-2013-0526");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("IBM 1754 GCM16 and GCM32 Global Console Managers Multiple Command Execution Vulnerabilities");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61816");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-19 15:12:16 +0200 (Mon, 19 Aug 2013)");
 script_description(desc);
 script_summary("Determine if firmware version is greater than 1.18.0.22011");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_snmp_sysdesc.nasl","gb_ibm_gcm_kvm_default_login.nasl");
 script_require_ports("Services/snmp", 161, 443);
 script_require_keys("SNMP/sysdesc","GCM_16_32/installed");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }

 exit(0);
}

include("version_func.inc");

if(!get_kb_item("GCM_16_32/installed"))exit(0);   
if(!sysdesc = get_kb_item("SNMP/sysdesc"))exit(0);

if(!egrep(pattern:"^GCM(16|32)", string:sysdesc))exit(0);

version = eregmatch(pattern:"GCM(16|32) ([0-9.]+)", string: sysdesc);
if(isnull(version[2]))exit(0);

vers = version[2];

if(version_is_less(version:vers, test_version:"1.18.0.22011")) {

  security_hole(port:443);
  exit(0);

}

exit(99);

