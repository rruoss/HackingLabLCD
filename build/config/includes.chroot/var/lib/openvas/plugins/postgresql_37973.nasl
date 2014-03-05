###############################################################################
# OpenVAS Vulnerability Test
# $Id: postgresql_37973.nasl 14 2013-10-27 12:33:37Z jan $
#
# PostgreSQL 'bitsubstr' Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Update By : Antu Sanadi <santu@secpod.com> 2010-02-04 #7085
# Updated the CVE-2010-0442 and version check according to CVE.
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
tag_summary = "PostgreSQL is prone to a buffer-overflow vulnerability because the
application fails to perform adequate boundary checks on user-
supplied data.

Attackers can exploit this issue to execute arbitrary code with
elevated privileges or crash the affected application.

PostgreSQL version 8.0.x, 8.1.x, 8.3.x is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100470";
CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-28 18:48:47 +0100 (Thu, 28 Jan 2010)");
 script_cve_id("CVE-2010-0442");
 script_bugtraq_id(37973);
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("PostgreSQL 'bitsubstr' Buffer Overflow Vulnerability");
desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.postgresql.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37973");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55902");
 script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/postgresql-8023-bitsubstr-overflow.html");

 script_description(desc);
 script_summary("Determine if PostgreSQL version");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("postgresql_detect.nasl");
 script_require_ports("Services/postgresql", 5432);
 script_require_keys("PostgreSQL/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);

if(!port)port = 5432;

if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_in_range(version:ver, test_version:"8.0", test_version2:"8.0.23") ||
   version_in_range(version:ver, test_version:"8.1", test_version2:"8.1.11") ||
   version_in_range(version:ver, test_version:"8.3", test_version2:"8.3.8")){
  security_hole(port:port);
  exit(0);
}

exit(0);
