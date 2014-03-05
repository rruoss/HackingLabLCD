###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for python-django MDVSA-2012:143 (python-django)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Multiple vulnerabilities has been discovered and corrected in
  python-django:

  The (1) django.http.HttpResponseRedirect and (2)
  django.http.HttpResponsePermanentRedirect classes in Django before
  1.3.2 and 1.4.x before 1.4.1 do not validate the scheme of a redirect
  target, which might allow remote attackers to conduct cross-site
  scripting (XSS) attacks via a data: URL (CVE-2012-3442).

  The django.forms.ImageField class in the form system in Django
  before 1.3.2 and 1.4.x before 1.4.1 completely decompresses image
  data during image validation, which allows remote attackers to cause
  a denial of service (memory consumption) by uploading an image file
  (CVE-2012-3443).

  The get_image_dimensions function in the image-handling functionality
  in Django before 1.3.2 and 1.4.x before 1.4.1 uses a constant chunk
  size in all attempts to determine dimensions, which allows remote
  attackers to cause a denial of service (process or thread consumption)
  via a large TIFF image (CVE-2012-3444).

  The updated packages have been upgraded to the 1.3.3 version which
  is not vulnerable to these issues.";

tag_affected = "python-django on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:143");
  script_id(831728);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"creation_date", value:"2012-08-24 09:57:26 +0530 (Fri, 24 Aug 2012)");
  script_cve_id("CVE-2012-3442", "CVE-2012-3443", "CVE-2012-3444");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVSA", value: "2012:143");
  script_name("Mandriva Update for python-django MDVSA-2012:143 (python-django)");

  script_description(desc);
  script_summary("Check for the Version of python-django");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.3.3~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.3.3~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
