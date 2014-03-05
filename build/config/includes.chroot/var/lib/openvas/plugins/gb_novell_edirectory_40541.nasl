###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edirectory_40541.nasl 14 2013-10-27 12:33:37Z jan $
#
# Novell eDirectory Multiple Remote Vulnerabilities
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
tag_summary = "Novell eDirectory is prone to multiple remote vulnerabilities.

Successful exploits may allow attackers to execute arbitrary code
within the context of the affected application or cause denial-of-
service conditions.

These issues affect eDirectory versions prior to 8.8 SP5 Patch 4.";

tag_solution = "The vendor has released fixes. Please see the references for details.";

if (description)
{
 script_id(100667);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-04 13:05:19 +0200 (Fri, 04 Jun 2010)");
 script_bugtraq_id(40541);
 script_cve_id("CVE-2009-4653");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_name("Novell eDirectory Multiple Remote Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40541");
 script_xref(name : "URL" , value : "http://www.novell.com/support/viewContent.do?externalId=3426981");
 script_xref(name : "URL" , value : "http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5076150.html");
 script_xref(name : "URL" , value : "http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5076151.html");
 script_xref(name : "URL" , value : "http://www.novell.com/products/edirectory/");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if eDirectory version is <= 8.8 SP5 Patch 3");
 script_category(ACT_GATHER_INFO);
 script_family("General");
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

           if(revision && revision < 2050413) { # < eDirectory 8.8 SP5 Patch 4 (20504.13)
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
  security_hole(port:port);
  exit(0);
}

exit(0);
