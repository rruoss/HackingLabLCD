###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_edirectory_38157.nasl 14 2013-10-27 12:33:37Z jan $
#
# Novell eDirectory eMBox SOAP Request Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Updated the CVE.
#  - Rachana Shetty <srachana@secpod.com> on 2010-02-22 #7360
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
tag_summary = "Novell eDirectory is prone to a denial-of-service vulnerability.

Remote attackers can exploit this issue to crash the application,
denying service to legitimate users.

Versions prior to Novell eDirectory 8.8 SP5 Patch 3 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100492);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-10 12:17:39 +0100 (Wed, 10 Feb 2010)");
 script_cve_id("CVE-2010-0666");
 script_bugtraq_id(38157);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Novell eDirectory eMBox SOAP Request Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38157");
 script_xref(name : "URL" , value : "http://www.novell.com/support/viewContent.do?externalId=3426981");
 script_xref(name : "URL" , value : "http://www.novell.com");

 script_description(desc);
 script_summary("Determine if eDirectory version is < 8.8 SP5 Patch 3 ");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("novell_edirectory_detect.nasl");
 script_require_ports("Services/ldap", 389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/ldap");
if(!port)exit(0);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("ldap/", port,"/eDirectory")))exit(0);
if(!isnull(version)) {

  versions = split(version,sep: " ", keep:FALSE);

  if(!isnull(versions[0])) {
     major = versions[0];
  } else {
     exit(0);
  }

  if(!isnull(versions[1])) {
     if("SP" >< versions[1]) {
       sp = versions[1];
       sp -= "SP";
       sp = int(sp);
     } else {
       revision = versions[1];
     }
  }

  if(sp && !isnull(versions[2])) {
     revision = versions[2];
  }

  if(revision) {
   revision -= "(";
   revision -= ")";
   revision -= ".";
   revision = int(revision);
  }

  if(major == "8.8") {
     if(sp && sp > 0) {
        if(sp == 5) {

           if(revision && revision < 2050315) { # < eDirectory 8.8 SP5 Patch 3 (20503.15)
              vuln = TRUE;
           }

        } else {

          if(sp < 5) {
            vuln = TRUE;
          }

       }
     } else {
       vuln = TRUE;
   }
  }
}

if(vuln) {
  security_warning(port:port);
  exit(0);
}

exit(0);



