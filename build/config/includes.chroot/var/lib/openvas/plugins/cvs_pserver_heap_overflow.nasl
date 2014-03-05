###############################################################################
# OpenVAS Vulnerability Test
# $Id: cvs_pserver_heap_overflow.nasl 15 2013-10-27 12:49:54Z jan $
#
# CVS Malformed Entry Modified and Unchanged Flag Insertion Heap Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "CVS is prone to a remote heap overflow vulnerability. This issue
presents itself during the handling of user-supplied input for entry
lines with 'modified' and 'unchanged' flags. This vulnerability can
allow an attacker to overflow a vulnerable buffer on the heap,
possibly leading to arbitrary code execution.

CVS versions 1.11.15 and prior and CVS feature versions 1.12.7 and
prior are prone to this issue.

**UPDATE: Symantec has confirmed that this vulnerability is being
actively exploited in the wild. Administrators are urged to
upgrade and block external access to potentially vulnerable
servers, if possible.";


tag_solution = "CVS versions 1.11.16 and 1.12.8 have been released to address
this issue.";

if (description)
{
 script_id(100289);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
 script_bugtraq_id(10384);
 script_cve_id("CVE-2004-0396");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("CVS Malformed Entry Modified and Unchanged Flag Insertion Heap Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/10384");
 script_xref(name : "URL" , value : "http://security.e-matters.de/advisories/072004.html?SID=384b888de96e3bce19306db8577fca26");
 script_xref(name : "URL" , value : "http://support.coresecurity.com/impact/exploits/62024ecea12fe1bbd01479065b3a1797.html");
 script_xref(name : "URL" , value : "http://ccvs.cvshome.org/");
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=openbsd-security-announce&amp;m=108508894405639&amp;w=2");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2004-190.html");
 script_xref(name : "URL" , value : "http://www.us-cert.gov/cas/techalerts/TA04-147A.html");

 script_description(desc);
 script_summary("Determine if CVS is prone to a remote heap overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("cvspserver_version.nasl");
 script_require_ports("Services/cvspserver", 2401);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;

if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("cvs/", port, "/version")))exit(0);
if(!isnull(version)) {

  if(version_is_less(version: version, test_version: "1.11.15") ||
     version_in_range(version: version, test_version: "1.12", test_version2: "1.12.7")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
