###################################################################
# OpenVAS Vulnerability Test
#
# Mac OS X Version
#
# LSS-NVT-2009-005
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_summary = "This script gets the Mac OS X version from other plugins
and fills in the necessary CVE IDs. Yes, it is that simple.";

if (description) {
 
 script_id(102005);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-17 12:37:40 +0100 (Tue, 17 Nov 2009)");
 
 script_name("Mac OS X Version");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 
 script_summary("Fills in CVE IDs depending on Mac OS X version");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("Copyright (C) 2009 LSS");
 script_dependencies("os_fingerprint.nasl", "gather-package-list.nasl");
 script_require_keys("Host/OS", "ssh/login/osx_version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# get the os string
os = get_kb_item("ssh/login/osx_name") + " " + get_kb_item("ssh/login/osx_version");
if (!os) os = get_kb_item("Host/OS");
if (!os) os = get_kb_item("Host/OS/ICMP");
if (!os) exit(0);

if ("Mac OS X" >< os) { 

 # search for the digits behind the last dot
 # (OS X versioning is 10.X.Y, we want the Y)
 version = strstr(os, ".");
 version = substr(version, "1");
 version = strstr(version, ".");
 version = substr(version, "1");
 version = int(version);

 if ("10.5." >< os) {
  if (version < 7) {
   report="The remote host is not running the latest Mac OS X 10.5.
Please update to the latest version.";
   set_kb_item(name:"CVE-2008-2939", value:TRUE);
   set_kb_item(name:"CVE-2008-0456", value:TRUE);
   set_kb_item(name:"CVE-2009-0154", value:TRUE);
   set_kb_item(name:"CVE-2009-0025", value:TRUE);
   set_kb_item(name:"CVE-2009-0144", value:TRUE);
   set_kb_item(name:"CVE-2009-0157", value:TRUE);
   set_kb_item(name:"CVE-2009-0145", value:TRUE);
   set_kb_item(name:"CVE-2009-0155", value:TRUE);
   set_kb_item(name:"CVE-2009-0146", value:TRUE);
   set_kb_item(name:"CVE-2009-0147", value:TRUE);
   set_kb_item(name:"CVE-2009-0165", value:TRUE);
   set_kb_item(name:"CVE-2009-0148", value:TRUE);
   set_kb_item(name:"CVE-2009-0164", value:TRUE);
   set_kb_item(name:"CVE-2009-0150", value:TRUE);
   set_kb_item(name:"CVE-2009-0149", value:TRUE);
   set_kb_item(name:"CVE-2004-1184", value:TRUE);
   set_kb_item(name:"CVE-2004-1185", value:TRUE);
   set_kb_item(name:"CVE-2004-1186", value:TRUE);
   set_kb_item(name:"CVE-2008-3863", value:TRUE);
   set_kb_item(name:"CVE-2009-0519", value:TRUE);
   set_kb_item(name:"CVE-2009-0520", value:TRUE);
   set_kb_item(name:"CVE-2009-0114", value:TRUE);
   set_kb_item(name:"CVE-2009-0942", value:TRUE);
   set_kb_item(name:"CVE-2009-0943", value:TRUE);
   set_kb_item(name:"CVE-2009-0152", value:TRUE);
   set_kb_item(name:"CVE-2009-0153", value:TRUE);
   set_kb_item(name:"CVE-2008-3651", value:TRUE);
   set_kb_item(name:"CVE-2008-3652", value:TRUE);
   set_kb_item(name:"CVE-2009-0845", value:TRUE);
   set_kb_item(name:"CVE-2009-0846", value:TRUE);
   set_kb_item(name:"CVE-2009-0847", value:TRUE);
   set_kb_item(name:"CVE-2009-0844", value:TRUE);
   set_kb_item(name:"CVE-2008-1517", value:TRUE);
   set_kb_item(name:"CVE-2009-0156", value:TRUE);
   set_kb_item(name:"CVE-2008-3529", value:TRUE);
   set_kb_item(name:"CVE-2008-4309", value:TRUE);
   set_kb_item(name:"CVE-2009-0021", value:TRUE);
   set_kb_item(name:"CVE-2009-0159", value:TRUE);
   set_kb_item(name:"CVE-2008-3530", value:TRUE);
   set_kb_item(name:"CVE-2008-5077", value:TRUE);
   set_kb_item(name:"CVE-2008-3659", value:TRUE);
   set_kb_item(name:"CVE-2008-2829", value:TRUE);
   set_kb_item(name:"CVE-2008-3660", value:TRUE);
   set_kb_item(name:"CVE-2008-2666", value:TRUE);
   set_kb_item(name:"CVE-2008-2371", value:TRUE);
   set_kb_item(name:"CVE-2008-2665", value:TRUE);
   set_kb_item(name:"CVE-2008-3658", value:TRUE);
   set_kb_item(name:"CVE-2008-5557", value:TRUE);
   set_kb_item(name:"CVE-2009-0160", value:TRUE);
   set_kb_item(name:"CVE-2009-0010", value:TRUE);
   set_kb_item(name:"CVE-2008-3443", value:TRUE);
   set_kb_item(name:"CVE-2008-3655", value:TRUE);
   set_kb_item(name:"CVE-2008-3656", value:TRUE);
   set_kb_item(name:"CVE-2008-3657", value:TRUE);
   set_kb_item(name:"CVE-2008-3790", value:TRUE);
   set_kb_item(name:"CVE-2009-0161", value:TRUE);
   set_kb_item(name:"CVE-2009-0162", value:TRUE);
   set_kb_item(name:"CVE-2009-0944", value:TRUE);
   set_kb_item(name:"CVE-2009-0158", value:TRUE);
   set_kb_item(name:"CVE-2009-1717", value:TRUE);
   set_kb_item(name:"CVE-2009-0945", value:TRUE);
   set_kb_item(name:"CVE-2008-2383", value:TRUE);
   set_kb_item(name:"CVE-2008-1382", value:TRUE);
   set_kb_item(name:"CVE-2009-0040", value:TRUE);
   set_kb_item(name:"CVE-2009-0946", value:TRUE);
   set_kb_item(name:"CVE-2009-0142", value:TRUE);
   set_kb_item(name:"CVE-2009-0009", value:TRUE);
   set_kb_item(name:"CVE-2009-0020", value:TRUE);
   set_kb_item(name:"CVE-2009-0011", value:TRUE);
   set_kb_item(name:"CVE-2009-0012", value:TRUE);
   set_kb_item(name:"CVE-2008-5183", value:TRUE);
   set_kb_item(name:"CVE-2009-0013", value:TRUE);
   set_kb_item(name:"CVE-2007-4565", value:TRUE);
   set_kb_item(name:"CVE-2008-2711", value:TRUE);
   set_kb_item(name:"CVE-2009-0014", value:TRUE);
   set_kb_item(name:"CVE-2009-0015", value:TRUE);
   set_kb_item(name:"CVE-2008-1927", value:TRUE);
   set_kb_item(name:"CVE-2009-0017", value:TRUE);
   set_kb_item(name:"CVE-2008-1679", value:TRUE);
   set_kb_item(name:"CVE-2008-1721", value:TRUE);
   set_kb_item(name:"CVE-2008-1887", value:TRUE);
   set_kb_item(name:"CVE-2008-2315", value:TRUE);
   set_kb_item(name:"CVE-2008-2316", value:TRUE);
   set_kb_item(name:"CVE-2008-3142", value:TRUE);
   set_kb_item(name:"CVE-2008-3144", value:TRUE);
   set_kb_item(name:"CVE-2008-4864", value:TRUE);
   set_kb_item(name:"CVE-2007-4965", value:TRUE);
   set_kb_item(name:"CVE-2008-5031", value:TRUE);
   set_kb_item(name:"CVE-2009-0018", value:TRUE);
   set_kb_item(name:"CVE-2009-0019", value:TRUE);
   set_kb_item(name:"CVE-2009-0137", value:TRUE);
   set_kb_item(name:"CVE-2009-0138", value:TRUE);
   set_kb_item(name:"CVE-2009-0139", value:TRUE);
   set_kb_item(name:"CVE-2009-0140", value:TRUE);
   set_kb_item(name:"CVE-2008-1377", value:TRUE);
   set_kb_item(name:"CVE-2008-1379", value:TRUE);
   set_kb_item(name:"CVE-2008-2360", value:TRUE);
   set_kb_item(name:"CVE-2008-2361", value:TRUE);
   set_kb_item(name:"CVE-2008-2362", value:TRUE);
   set_kb_item(name:"CVE-2009-0141", value:TRUE);
  }
  if (version < 6) {
   set_kb_item(name:"CVE-2008-4236", value:TRUE);
   set_kb_item(name:"CVE-2008-4217", value:TRUE);
   set_kb_item(name:"CVE-2008-3623", value:TRUE);
   set_kb_item(name:"CVE-2008-3170", value:TRUE);
   set_kb_item(name:"CVE-2008-4234", value:TRUE);
   set_kb_item(name:"CVE-2007-4324", value:TRUE);
   set_kb_item(name:"CVE-2007-6243", value:TRUE);
   set_kb_item(name:"CVE-2008-3873", value:TRUE);
   set_kb_item(name:"CVE-2008-4401", value:TRUE);
   set_kb_item(name:"CVE-2008-4503", value:TRUE);
   set_kb_item(name:"CVE-2008-4818", value:TRUE);
   set_kb_item(name:"CVE-2008-4819", value:TRUE);
   set_kb_item(name:"CVE-2008-4820", value:TRUE);
   set_kb_item(name:"CVE-2008-4821", value:TRUE);
   set_kb_item(name:"CVE-2008-4822", value:TRUE);
   set_kb_item(name:"CVE-2008-4823", value:TRUE);
   set_kb_item(name:"CVE-2008-4824", value:TRUE);
   set_kb_item(name:"CVE-2008-5361", value:TRUE);
   set_kb_item(name:"CVE-2008-5362", value:TRUE);
   set_kb_item(name:"CVE-2008-5363", value:TRUE);
   set_kb_item(name:"CVE-2008-4218", value:TRUE);
   set_kb_item(name:"CVE-2008-4219", value:TRUE);
   set_kb_item(name:"CVE-2008-4220", value:TRUE);
   set_kb_item(name:"CVE-2008-4221", value:TRUE);
   set_kb_item(name:"CVE-2008-1391", value:TRUE);
   set_kb_item(name:"CVE-2008-4237", value:TRUE);
   set_kb_item(name:"CVE-2008-4222", value:TRUE);
   set_kb_item(name:"CVE-2008-4224", value:TRUE);
   set_kb_item(name:"CVE-2007-6420", value:TRUE);
   set_kb_item(name:"CVE-2008-1678", value:TRUE);
   set_kb_item(name:"CVE-2008-2364", value:TRUE);
   set_kb_item(name:"CVE-2008-3642", value:TRUE);
   set_kb_item(name:"CVE-2008-3641", value:TRUE);
   set_kb_item(name:"CVE-2008-3643", value:TRUE);
   set_kb_item(name:"CVE-2008-1767", value:TRUE);
   set_kb_item(name:"CVE-2008-3645", value:TRUE);
   set_kb_item(name:"CVE-2007-4850", value:TRUE);
   set_kb_item(name:"CVE-2008-0674", value:TRUE);
   set_kb_item(name:"CVE-2008-2371", value:TRUE);
   set_kb_item(name:"CVE-2008-3646", value:TRUE);
   set_kb_item(name:"CVE-2008-3647", value:TRUE);
   set_kb_item(name:"CVE-2008-4211", value:TRUE);
   set_kb_item(name:"CVE-2008-4212", value:TRUE);
   set_kb_item(name:"CVE-2008-4214", value:TRUE);
   set_kb_item(name:"CVE-2008-2712", value:TRUE);
   set_kb_item(name:"CVE-2008-4101", value:TRUE);
   set_kb_item(name:"CVE-2008-2712", value:TRUE);
   set_kb_item(name:"CVE-2008-3432", value:TRUE);
   set_kb_item(name:"CVE-2008-3294", value:TRUE);
  }
  if (version < 5) {
   set_kb_item(name:"CVE-2008-2305", value:TRUE);
   set_kb_item(name:"CVE-2008-2329", value:TRUE);
   set_kb_item(name:"CVE-2008-2331", value:TRUE);
   set_kb_item(name:"CVE-2008-3613", value:TRUE);
   set_kb_item(name:"CVE-2008-2327", value:TRUE);
   set_kb_item(name:"CVE-2008-2332", value:TRUE);
   set_kb_item(name:"CVE-2008-3608", value:TRUE);
   set_kb_item(name:"CVE-2008-1382", value:TRUE);
   set_kb_item(name:"CVE-2008-3609", value:TRUE);
   set_kb_item(name:"CVE-2008-1447", value:TRUE);
   set_kb_item(name:"CVE-2008-3610", value:TRUE);
   set_kb_item(name:"CVE-2008-1447", value:TRUE);
   set_kb_item(name:"CVE-2008-1483", value:TRUE);
   set_kb_item(name:"CVE-2008-1657", value:TRUE);
   set_kb_item(name:"CVE-2008-3614", value:TRUE);
   set_kb_item(name:"CVE-2008-2376", value:TRUE);
   set_kb_item(name:"CVE-2008-3616", value:TRUE);
   set_kb_item(name:"CVE-2008-3617", value:TRUE);
   set_kb_item(name:"CVE-2008-3618", value:TRUE);
   set_kb_item(name:"CVE-2008-3619", value:TRUE);
   set_kb_item(name:"CVE-2008-3621", value:TRUE);
   set_kb_item(name:"CVE-2008-3622", value:TRUE);
   set_kb_item(name:"CVE-2008-2830", value:TRUE);
   set_kb_item(name:"CVE-2008-1447", value:TRUE);
   set_kb_item(name:"CVE-2008-2320", value:TRUE);
   set_kb_item(name:"CVE-2008-2321", value:TRUE);
   set_kb_item(name:"CVE-2008-2322", value:TRUE);
   set_kb_item(name:"CVE-2008-2323", value:TRUE);
   set_kb_item(name:"CVE-2008-2952", value:TRUE);
   set_kb_item(name:"CVE-2007-5135", value:TRUE);
   set_kb_item(name:"CVE-2008-2051", value:TRUE);
   set_kb_item(name:"CVE-2008-2050", value:TRUE);
   set_kb_item(name:"CVE-2007-4850", value:TRUE);
   set_kb_item(name:"CVE-2008-0599", value:TRUE);
   set_kb_item(name:"CVE-2008-0674", value:TRUE);
   set_kb_item(name:"CVE-2008-2325", value:TRUE);
   set_kb_item(name:"CVE-2007-6199", value:TRUE);
   set_kb_item(name:"CVE-2007-6200", value:TRUE);
  }
  if (version < 4) {
   set_kb_item(name:"CVE-2008-2309", value:TRUE);
   set_kb_item(name:"CVE-2008-2310", value:TRUE);
   set_kb_item(name:"CVE-2008-2314", value:TRUE);
   set_kb_item(name:"CVE-2008-0960", value:TRUE);
   set_kb_item(name:"CVE-2008-2662", value:TRUE);
   set_kb_item(name:"CVE-2008-2663", value:TRUE);
   set_kb_item(name:"CVE-2008-2664", value:TRUE);
   set_kb_item(name:"CVE-2008-2725", value:TRUE);
   set_kb_item(name:"CVE-2008-2726", value:TRUE);
   set_kb_item(name:"CVE-2008-1145", value:TRUE);
   set_kb_item(name:"CVE-2008-1105", value:TRUE);
   set_kb_item(name:"CVE-2007-6276", value:TRUE);
   set_kb_item(name:"CVE-2008-2307", value:TRUE);
  }
  if (version < 3) {
   set_kb_item(name:"CVE-2008-1027", value:TRUE);
   set_kb_item(name:"CVE-2008-1577", value:TRUE);
   set_kb_item(name:"CVE-2008-1575", value:TRUE);
   set_kb_item(name:"CVE-2008-1580", value:TRUE);
   set_kb_item(name:"CVE-2008-1030", value:TRUE);
   set_kb_item(name:"CVE-2008-1031", value:TRUE);
   set_kb_item(name:"CVE-2008-1032", value:TRUE);
   set_kb_item(name:"CVE-2008-1033", value:TRUE);
   set_kb_item(name:"CVE-2007-5275", value:TRUE);
   set_kb_item(name:"CVE-2007-6243", value:TRUE);
   set_kb_item(name:"CVE-2007-6637", value:TRUE);
   set_kb_item(name:"CVE-2007-6019", value:TRUE);
   set_kb_item(name:"CVE-2007-0071", value:TRUE);
   set_kb_item(name:"CVE-2008-1655", value:TRUE);
   set_kb_item(name:"CVE-2008-1654", value:TRUE);
   set_kb_item(name:"CVE-2008-1035", value:TRUE);
   set_kb_item(name:"CVE-2008-1036", value:TRUE);
   set_kb_item(name:"CVE-2008-1573", value:TRUE);
   set_kb_item(name:"CVE-2007-5266", value:TRUE);
   set_kb_item(name:"CVE-2007-5268", value:TRUE);
   set_kb_item(name:"CVE-2007-5269", value:TRUE);
   set_kb_item(name:"CVE-2008-1574", value:TRUE);
   set_kb_item(name:"CVE-2008-0177", value:TRUE);
   set_kb_item(name:"CVE-2007-6359", value:TRUE);
   set_kb_item(name:"CVE-2007-6612", value:TRUE);
   set_kb_item(name:"CVE-2008-1578", value:TRUE);
   set_kb_item(name:"CVE-2008-1579", value:TRUE);
   set_kb_item(name:"CVE-2008-0044", value:TRUE);
   set_kb_item(name:"CVE-2005-3352", value:TRUE);
   set_kb_item(name:"CVE-2006-3747", value:TRUE);
   set_kb_item(name:"CVE-2007-3847", value:TRUE);
   set_kb_item(name:"CVE-2007-5000", value:TRUE);
   set_kb_item(name:"CVE-2007-6388", value:TRUE);
   set_kb_item(name:"CVE-2007-6203", value:TRUE);
   set_kb_item(name:"CVE-2007-6421", value:TRUE);
   set_kb_item(name:"CVE-2008-0005", value:TRUE);
   set_kb_item(name:"CVE-2006-5752", value:TRUE);
   set_kb_item(name:"CVE-2008-0046", value:TRUE);
   set_kb_item(name:"CVE-2008-0047", value:TRUE);
   set_kb_item(name:"CVE-2008-0053", value:TRUE);
   set_kb_item(name:"CVE-2008-0882", value:TRUE);
   set_kb_item(name:"CVE-2007-6109", value:TRUE);
   set_kb_item(name:"CVE-2007-5795", value:TRUE);
   set_kb_item(name:"CVE-2008-0060", value:TRUE);
   set_kb_item(name:"CVE-2008-0987", value:TRUE);
   set_kb_item(name:"CVE-2007-5901", value:TRUE);
   set_kb_item(name:"CVE-2007-5971", value:TRUE);
   set_kb_item(name:"CVE-2008-0062", value:TRUE);
   set_kb_item(name:"CVE-2008-0063", value:TRUE);
   set_kb_item(name:"CVE-2008-0989", value:TRUE);
   set_kb_item(name:"CVE-2007-4752", value:TRUE);
   set_kb_item(name:"CVE-2008-0992", value:TRUE);
   set_kb_item(name:"CVE-2007-1659", value:TRUE);
   set_kb_item(name:"CVE-2007-1660", value:TRUE);
   set_kb_item(name:"CVE-2007-1661", value:TRUE);
   set_kb_item(name:"CVE-2007-1662", value:TRUE);
   set_kb_item(name:"CVE-2007-4766", value:TRUE);
   set_kb_item(name:"CVE-2007-4767", value:TRUE);
   set_kb_item(name:"CVE-2007-4768", value:TRUE);
   set_kb_item(name:"CVE-2007-4887", value:TRUE);
   set_kb_item(name:"CVE-2008-0993", value:TRUE);
   set_kb_item(name:"CVE-2008-0994", value:TRUE);
   set_kb_item(name:"CVE-2008-0995", value:TRUE);
   set_kb_item(name:"CVE-2008-0996", value:TRUE);
   set_kb_item(name:"CVE-2008-0998", value:TRUE);
   set_kb_item(name:"CVE-2008-0999", value:TRUE);
   set_kb_item(name:"CVE-2008-1000", value:TRUE);
   set_kb_item(name:"CVE-2006-3334", value:TRUE);
   set_kb_item(name:"CVE-2006-5793", value:TRUE);
   set_kb_item(name:"CVE-2007-2445", value:TRUE);
   set_kb_item(name:"CVE-2007-5266", value:TRUE);
   set_kb_item(name:"CVE-2007-5267", value:TRUE);
   set_kb_item(name:"CVE-2007-5268", value:TRUE);
   set_kb_item(name:"CVE-2007-5269", value:TRUE);
   set_kb_item(name:"CVE-2007-5958", value:TRUE);
   set_kb_item(name:"CVE-2008-0006", value:TRUE);
   set_kb_item(name:"CVE-2007-6427", value:TRUE);
   set_kb_item(name:"CVE-2007-6428", value:TRUE);
   set_kb_item(name:"CVE-2007-6429", value:TRUE);
  }
  if (version < 2) {
   set_kb_item(name:"CVE-2008-0035", value:TRUE);
   set_kb_item(name:"CVE-2008-0038", value:TRUE);
   set_kb_item(name:"CVE-2008-0040", value:TRUE);
   set_kb_item(name:"CVE-2008-0041", value:TRUE);
   set_kb_item(name:"CVE-2007-6015", value:TRUE);
   set_kb_item(name:"CVE-2008-0042", value:TRUE);
   set_kb_item(name:"CVE-2007-4568", value:TRUE);
   set_kb_item(name:"CVE-2008-0037", value:TRUE);
   set_kb_item(name:"CVE-2007-4709", value:TRUE);
   set_kb_item(name:"CVE-2007-4351", value:TRUE);
   set_kb_item(name:"CVE-2007-5849", value:TRUE);
   set_kb_item(name:"CVE-2007-5476", value:TRUE);
   set_kb_item(name:"CVE-2007-5854", value:TRUE);
   set_kb_item(name:"CVE-2007-6165", value:TRUE);
   set_kb_item(name:"CVE-2007-5116", value:TRUE);
   set_kb_item(name:"CVE-2007-4965", value:TRUE);
   set_kb_item(name:"CVE-2007-5856", value:TRUE);
   set_kb_item(name:"CVE-2007-5857", value:TRUE);
   set_kb_item(name:"CVE-2007-5770", value:TRUE);
   set_kb_item(name:"CVE-2007-5379", value:TRUE);
   set_kb_item(name:"CVE-2007-5380", value:TRUE);
   set_kb_item(name:"CVE-2007-6077", value:TRUE);
   set_kb_item(name:"CVE-2007-5858", value:TRUE);
   set_kb_item(name:"CVE-2007-4572", value:TRUE);
   set_kb_item(name:"CVE-2007-5398", value:TRUE);
   set_kb_item(name:"CVE-2006-0024", value:TRUE);
   set_kb_item(name:"CVE-2007-5863", value:TRUE);
   set_kb_item(name:"CVE-2007-5860", value:TRUE);
  }
  if (version < 1) {
   set_kb_item(name:"CVE-2007-4702", value:TRUE);
   set_kb_item(name:"CVE-2007-4703", value:TRUE);
   set_kb_item(name:"CVE-2007-4704", value:TRUE);
  }
 }
 if ("10.4." >< os) {
  if (version < 11) {
  report="The remote host is not running the latest Mac OS X 10.4.
Please update to the latest version";
   set_kb_item(name:"CVE-2007-3456", value:TRUE);
   set_kb_item(name:"CVE-2007-4678", value:TRUE);
   set_kb_item(name:"CVE-2005-0953", value:TRUE);
   set_kb_item(name:"CVE-2005-1260", value:TRUE);
   set_kb_item(name:"CVE-2007-4679", value:TRUE);
   set_kb_item(name:"CVE-2007-4680", value:TRUE);
   set_kb_item(name:"CVE-2007-0464", value:TRUE);
   set_kb_item(name:"CVE-2007-4681", value:TRUE);
   set_kb_item(name:"CVE-2007-4682", value:TRUE);
   set_kb_item(name:"CVE-2007-3999", value:TRUE);
   set_kb_item(name:"CVE-2007-4743", value:TRUE);
   set_kb_item(name:"CVE-2007-3749", value:TRUE);
   set_kb_item(name:"CVE-2007-4683", value:TRUE);
   set_kb_item(name:"CVE-2007-4684", value:TRUE);
   set_kb_item(name:"CVE-2007-4685", value:TRUE);
   set_kb_item(name:"CVE-2006-6127", value:TRUE);
   set_kb_item(name:"CVE-2007-4686", value:TRUE);
   set_kb_item(name:"CVE-2007-4687", value:TRUE);
   set_kb_item(name:"CVE-2007-4688", value:TRUE);
   set_kb_item(name:"CVE-2007-4269", value:TRUE);
   set_kb_item(name:"CVE-2007-4689", value:TRUE);
   set_kb_item(name:"CVE-2007-4267", value:TRUE);
   set_kb_item(name:"CVE-2007-4268", value:TRUE);
   set_kb_item(name:"CVE-2007-4690", value:TRUE);
   set_kb_item(name:"CVE-2007-4691", value:TRUE);
   set_kb_item(name:"CVE-2007-0646", value:TRUE);
   set_kb_item(name:"CVE-2007-4692", value:TRUE);
   set_kb_item(name:"CVE-2007-4693", value:TRUE);
   set_kb_item(name:"CVE-2007-4694", value:TRUE);
   set_kb_item(name:"CVE-2007-4695", value:TRUE);
   set_kb_item(name:"CVE-2007-4696", value:TRUE);
   set_kb_item(name:"CVE-2007-4697", value:TRUE);
   set_kb_item(name:"CVE-2007-4698", value:TRUE);
   set_kb_item(name:"CVE-2007-3758", value:TRUE);
   set_kb_item(name:"CVE-2007-3760", value:TRUE);
   set_kb_item(name:"CVE-2007-4671", value:TRUE);
   set_kb_item(name:"CVE-2007-3756", value:TRUE);
   set_kb_item(name:"CVE-2007-4699", value:TRUE);
   set_kb_item(name:"CVE-2007-4700", value:TRUE);
   set_kb_item(name:"CVE-2007-4701", value:TRUE);
   set_kb_item(name:"CVE-2005-0758", value:TRUE);
   set_kb_item(name:"CVE-2007-2403", value:TRUE);
   set_kb_item(name:"CVE-2007-2404", value:TRUE);
   set_kb_item(name:"CVE-2007-3745", value:TRUE);
   set_kb_item(name:"CVE-2007-3746", value:TRUE);
   set_kb_item(name:"CVE-2007-3747", value:TRUE);
   set_kb_item(name:"CVE-2004-0996", value:TRUE);
   set_kb_item(name:"CVE-2004-2541", value:TRUE);
   set_kb_item(name:"CVE-2005-0758", value:TRUE);
   set_kb_item(name:"CVE-2007-3748", value:TRUE);
   set_kb_item(name:"CVE-2007-2442", value:TRUE);
   set_kb_item(name:"CVE-2007-2443", value:TRUE);
   set_kb_item(name:"CVE-2007-2798", value:TRUE);
   set_kb_item(name:"CVE-2007-3744", value:TRUE);
   set_kb_item(name:"CVE-2007-2405", value:TRUE);
   set_kb_item(name:"CVE-2007-1001", value:TRUE);
   set_kb_item(name:"CVE-2007-1287", value:TRUE);
   set_kb_item(name:"CVE-2007-1460", value:TRUE);
   set_kb_item(name:"CVE-2007-1461", value:TRUE);
   set_kb_item(name:"CVE-2007-1484", value:TRUE);
   set_kb_item(name:"CVE-2007-1521", value:TRUE);
   set_kb_item(name:"CVE-2007-1583", value:TRUE);
   set_kb_item(name:"CVE-2007-1711", value:TRUE);
   set_kb_item(name:"CVE-2007-1717", value:TRUE);
   set_kb_item(name:"CVE-2007-2406", value:TRUE);
   set_kb_item(name:"CVE-2007-2446", value:TRUE);
   set_kb_item(name:"CVE-2007-2447", value:TRUE);
   set_kb_item(name:"CVE-2007-2407", value:TRUE);
   set_kb_item(name:"CVE-2007-2408", value:TRUE);
   set_kb_item(name:"CVE-2007-0478", value:TRUE);
   set_kb_item(name:"CVE-2007-2409", value:TRUE);
   set_kb_item(name:"CVE-2007-2410", value:TRUE);
   set_kb_item(name:"CVE-2007-3742", value:TRUE);
   set_kb_item(name:"CVE-2007-3944", value:TRUE);
  }
  if (version < 10) {
   set_kb_item(name:"CVE-2007-2242", value:TRUE);
   set_kb_item(name:"CVE-2007-2401", value:TRUE);
   set_kb_item(name:"CVE-2007-2399", value:TRUE);
   set_kb_item(name:"CVE-2007-0740", value:TRUE);
   set_kb_item(name:"CVE-2007-0493", value:TRUE);
   set_kb_item(name:"CVE-2007-0494", value:TRUE);
   set_kb_item(name:"CVE-2007-0495", value:TRUE);
   set_kb_item(name:"CVE-2007-0496", value:TRUE);
   set_kb_item(name:"CVE-2007-0750", value:TRUE);
   set_kb_item(name:"CVE-2007-0751", value:TRUE);
   set_kb_item(name:"CVE-2007-1558", value:TRUE);
   set_kb_item(name:"CVE-2007-1536", value:TRUE);
   set_kb_item(name:"CVE-2007-2390", value:TRUE);
   set_kb_item(name:"CVE-2007-2386", value:TRUE);
   set_kb_item(name:"CVE-2007-0752", value:TRUE);
   set_kb_item(name:"CVE-2006-5467", value:TRUE);
   set_kb_item(name:"CVE-2006-6303", value:TRUE);
   set_kb_item(name:"CVE-2006-4573", value:TRUE);
   set_kb_item(name:"CVE-2005-3011", value:TRUE);
   set_kb_item(name:"CVE-2007-0753", value:TRUE);
   set_kb_item(name:"CVE-2007-0745", value:TRUE);
   set_kb_item(name:"CVE-2007-0729", value:TRUE);
   set_kb_item(name:"CVE-2007-0725", value:TRUE);
   set_kb_item(name:"CVE-2007-0732", value:TRUE);
   set_kb_item(name:"CVE-2007-0734", value:TRUE);
   set_kb_item(name:"CVE-2006-5867", value:TRUE);
   set_kb_item(name:"CVE-2006-6652", value:TRUE);
   set_kb_item(name:"CVE-2006-0300", value:TRUE);
   set_kb_item(name:"CVE-2007-0646", value:TRUE);
   set_kb_item(name:"CVE-2007-0724", value:TRUE);
   set_kb_item(name:"CVE-2007-0465", value:TRUE);
   set_kb_item(name:"CVE-2006-6143", value:TRUE);
   set_kb_item(name:"CVE-2007-0957", value:TRUE);
   set_kb_item(name:"CVE-2007-1216", value:TRUE);
   set_kb_item(name:"CVE-2007-0735", value:TRUE);
   set_kb_item(name:"CVE-2007-0736", value:TRUE);
   set_kb_item(name:"CVE-2007-0737", value:TRUE);
   set_kb_item(name:"CVE-2007-0738", value:TRUE);
   set_kb_item(name:"CVE-2007-0739", value:TRUE);
   set_kb_item(name:"CVE-2007-0741", value:TRUE);
   set_kb_item(name:"CVE-2007-0744", value:TRUE);
   set_kb_item(name:"CVE-2007-0022", value:TRUE);
   set_kb_item(name:"CVE-2007-0743", value:TRUE);
   set_kb_item(name:"CVE-2007-0746", value:TRUE);
   set_kb_item(name:"CVE-2007-0747", value:TRUE);
  }
  if (version < 9) {
   set_kb_item(name:"CVE-2007-0719", value:TRUE);
   set_kb_item(name:"CVE-2007-0467", value:TRUE);
   set_kb_item(name:"CVE-2007-0720", value:TRUE);
   set_kb_item(name:"CVE-2007-0721", value:TRUE);
   set_kb_item(name:"CVE-2007-0722", value:TRUE);
   set_kb_item(name:"CVE-2006-6061", value:TRUE);
   set_kb_item(name:"CVE-2006-6062", value:TRUE);
   set_kb_item(name:"CVE-2006-5679", value:TRUE);
   set_kb_item(name:"CVE-2007-0229", value:TRUE);
   set_kb_item(name:"CVE-2007-0267", value:TRUE);
   set_kb_item(name:"CVE-2007-0299", value:TRUE);
   set_kb_item(name:"CVE-2007-0723", value:TRUE);
   set_kb_item(name:"CVE-2006-5330", value:TRUE);
   set_kb_item(name:"CVE-2006-6097", value:TRUE);
   set_kb_item(name:"CVE-2007-0318", value:TRUE);
   set_kb_item(name:"CVE-2007-0724", value:TRUE);
   set_kb_item(name:"CVE-2007-1071", value:TRUE);
   set_kb_item(name:"CVE-2007-0733", value:TRUE);
   set_kb_item(name:"CVE-2006-5836", value:TRUE);
   set_kb_item(name:"CVE-2006-6126", value:TRUE);
   set_kb_item(name:"CVE-2006-6129", value:TRUE);
   set_kb_item(name:"CVE-2006-6173", value:TRUE);
   set_kb_item(name:"CVE-2006-0430", value:TRUE);
   set_kb_item(name:"CVE-2006-1516", value:TRUE);
   set_kb_item(name:"CVE-2006-1517", value:TRUE);
   set_kb_item(name:"CVE-2006-2753", value:TRUE);
   set_kb_item(name:"CVE-2006-3081", value:TRUE);
   set_kb_item(name:"CVE-2006-4031", value:TRUE);
   set_kb_item(name:"CVE-2006-4226", value:TRUE);
   set_kb_item(name:"CVE-2006-3469", value:TRUE);
   set_kb_item(name:"CVE-2006-6130", value:TRUE);
   set_kb_item(name:"CVE-2007-0236", value:TRUE);
   set_kb_item(name:"CVE-2007-0726", value:TRUE);
   set_kb_item(name:"CVE-2006-0225", value:TRUE);
   set_kb_item(name:"CVE-2006-4924", value:TRUE);
   set_kb_item(name:"CVE-2006-5051", value:TRUE);
   set_kb_item(name:"CVE-2006-5052", value:TRUE);
   set_kb_item(name:"CVE-2007-0728", value:TRUE);
   set_kb_item(name:"CVE-2007-0588", value:TRUE);
   set_kb_item(name:"CVE-2007-0730", value:TRUE);
   set_kb_item(name:"CVE-2007-0731", value:TRUE);
   set_kb_item(name:"CVE-2007-0463", value:TRUE);
   set_kb_item(name:"CVE-2005-2959", value:TRUE);
   set_kb_item(name:"CVE-2006-4829", value:TRUE);
   set_kb_item(name:"CVE-2007-0197", value:TRUE);
   set_kb_item(name:"CVE-2007-0614", value:TRUE);
   set_kb_item(name:"CVE-2007-0710", value:TRUE);
   set_kb_item(name:"CVE-2007-0021", value:TRUE);
   set_kb_item(name:"CVE-2007-0023", value:TRUE);
   set_kb_item(name:"CVE-2007-0015", value:TRUE);
   set_kb_item(name:"CVE-2006-5681", value:TRUE);
   set_kb_item(name:"CVE-2006-5710", value:TRUE);
   set_kb_item(name:"CVE-2006-4396", value:TRUE);
   set_kb_item(name:"CVE-2006-4398", value:TRUE);
   set_kb_item(name:"CVE-2006-4400", value:TRUE);
   set_kb_item(name:"CVE-2006-4401", value:TRUE);
   set_kb_item(name:"CVE-2006-4402", value:TRUE);
   set_kb_item(name:"CVE-2006-4334", value:TRUE);
   set_kb_item(name:"CVE-2006-4335", value:TRUE);
   set_kb_item(name:"CVE-2006-4336", value:TRUE);
   set_kb_item(name:"CVE-2006-4337", value:TRUE);
   set_kb_item(name:"CVE-2006-4338", value:TRUE);
   set_kb_item(name:"CVE-2006-4404", value:TRUE);
   set_kb_item(name:"CVE-2006-2937", value:TRUE);
   set_kb_item(name:"CVE-2006-2940", value:TRUE);
   set_kb_item(name:"CVE-2006-3738", value:TRUE);
   set_kb_item(name:"CVE-2006-4339", value:TRUE);
   set_kb_item(name:"CVE-2006-4343", value:TRUE);
   set_kb_item(name:"CVE-2005-3962", value:TRUE);
   set_kb_item(name:"CVE-2006-1490", value:TRUE);
   set_kb_item(name:"CVE-2006-1990", value:TRUE);
   set_kb_item(name:"CVE-2006-5465", value:TRUE);
   set_kb_item(name:"CVE-2006-4406", value:TRUE);
   set_kb_item(name:"CVE-2006-3403", value:TRUE);
   set_kb_item(name:"CVE-2006-4408", value:TRUE);
   set_kb_item(name:"CVE-2006-4409", value:TRUE);
   set_kb_item(name:"CVE-2006-4411", value:TRUE);
   set_kb_item(name:"CVE-2006-4412", value:TRUE);
  }
  if (version < 8) {
   set_kb_item(name:"CVE-2006-4390", value:TRUE);
   set_kb_item(name:"CVE-2006-3311", value:TRUE);
   set_kb_item(name:"CVE-2006-3587", value:TRUE);
   set_kb_item(name:"CVE-2006-3588", value:TRUE);
   set_kb_item(name:"CVE-2006-4640", value:TRUE);
   set_kb_item(name:"CVE-2006-4391", value:TRUE);
   set_kb_item(name:"CVE-2006-4392", value:TRUE);
   set_kb_item(name:"CVE-2006-4397", value:TRUE);
   set_kb_item(name:"CVE-2006-4393", value:TRUE);
   set_kb_item(name:"CVE-2006-4394", value:TRUE);
   set_kb_item(name:"CVE-2006-4387", value:TRUE);
   set_kb_item(name:"CVE-2006-4395", value:TRUE);
   set_kb_item(name:"CVE-2006-1721", value:TRUE);
   set_kb_item(name:"CVE-2006-3946", value:TRUE);
   set_kb_item(name:"CVE-2006-4399", value:TRUE);
   set_kb_item(name:"CVE-2006-3507", value:TRUE);
   set_kb_item(name:"CVE-2006-3508", value:TRUE);
   set_kb_item(name:"CVE-2006-3509", value:TRUE);
   set_kb_item(name:"CVE-2006-1473", value:TRUE);
   set_kb_item(name:"CVE-2006-3495", value:TRUE);
   set_kb_item(name:"CVE-2006-3496", value:TRUE);
   set_kb_item(name:"CVE-2006-3459", value:TRUE);
   set_kb_item(name:"CVE-2006-3461", value:TRUE);
   set_kb_item(name:"CVE-2006-3462", value:TRUE);
   set_kb_item(name:"CVE-2006-3465", value:TRUE);
   set_kb_item(name:"CVE-2006-3497", value:TRUE);
   set_kb_item(name:"CVE-2006-3498", value:TRUE);
   set_kb_item(name:"CVE-2006-3499", value:TRUE);
   set_kb_item(name:"CVE-2006-3500", value:TRUE);
   set_kb_item(name:"CVE-2005-2335", value:TRUE);
   set_kb_item(name:"CVE-2005-3088", value:TRUE);
   set_kb_item(name:"CVE-2005-4348", value:TRUE);
   set_kb_item(name:"CVE-2006-0321", value:TRUE);
   set_kb_item(name:"CVE-2005-0988", value:TRUE);
   set_kb_item(name:"CVE-2005-1228", value:TRUE);
   set_kb_item(name:"CVE-2006-0392", value:TRUE);
   set_kb_item(name:"CVE-2006-3501", value:TRUE);
   set_kb_item(name:"CVE-2006-3502", value:TRUE);
   set_kb_item(name:"CVE-2006-3503", value:TRUE);
   set_kb_item(name:"CVE-2006-3504", value:TRUE);
   set_kb_item(name:"CVE-2006-0393", value:TRUE);
   set_kb_item(name:"CVE-2005-0488", value:TRUE);
   set_kb_item(name:"CVE-2006-3505", value:TRUE);
   set_kb_item(name:"CVE-2006-3459", value:TRUE);
   set_kb_item(name:"CVE-2006-3461", value:TRUE);
   set_kb_item(name:"CVE-2006-3462", value:TRUE);
   set_kb_item(name:"CVE-2006-3465", value:TRUE);
  }
  if (version < 7) {
   set_kb_item(name:"CVE-2006-1468", value:TRUE);
   set_kb_item(name:"CVE-2006-1469", value:TRUE);
   set_kb_item(name:"CVE-2006-1471", value:TRUE);
   set_kb_item(name:"CVE-2006-1470", value:TRUE);
   set_kb_item(name:"CVE-2006-1439", value:TRUE);
   set_kb_item(name:"CVE-2006-1982", value:TRUE);
   set_kb_item(name:"CVE-2006-1983", value:TRUE);
   set_kb_item(name:"CVE-2006-1984", value:TRUE);
   set_kb_item(name:"CVE-2006-1985", value:TRUE);
   set_kb_item(name:"CVE-2006-1440", value:TRUE);
   set_kb_item(name:"CVE-2006-1441", value:TRUE);
   set_kb_item(name:"CVE-2006-1442", value:TRUE);
   set_kb_item(name:"CVE-2006-1443", value:TRUE);
   set_kb_item(name:"CVE-2006-1444", value:TRUE);
   set_kb_item(name:"CVE-2006-1448", value:TRUE);
   set_kb_item(name:"CVE-2006-1445", value:TRUE);
   set_kb_item(name:"CVE-2005-2628", value:TRUE);
   set_kb_item(name:"CVE-2006-0024", value:TRUE);
   set_kb_item(name:"CVE-2006-1552", value:TRUE);
   set_kb_item(name:"CVE-2006-1446", value:TRUE);
   set_kb_item(name:"CVE-2006-1447", value:TRUE);
   set_kb_item(name:"CVE-2005-4077", value:TRUE);
   set_kb_item(name:"CVE-2006-1449", value:TRUE);
   set_kb_item(name:"CVE-2006-1450", value:TRUE);
   set_kb_item(name:"CVE-2006-1451", value:TRUE);
   set_kb_item(name:"CVE-2006-1452", value:TRUE);
   set_kb_item(name:"CVE-2006-1453", value:TRUE);
   set_kb_item(name:"CVE-2006-1454", value:TRUE);
   set_kb_item(name:"CVE-2006-1455", value:TRUE);
   set_kb_item(name:"CVE-2006-1456", value:TRUE);
   set_kb_item(name:"CVE-2005-2337", value:TRUE);
   set_kb_item(name:"CVE-2006-1457", value:TRUE);
  }
  if (version < 6) {
   set_kb_item(name:"CVE-2006-0401", value:TRUE);
   set_kb_item(name:"CVE-2006-0400", value:TRUE);
   set_kb_item(name:"CVE-2006-0396", value:TRUE);
   set_kb_item(name:"CVE-2006-0397", value:TRUE);
   set_kb_item(name:"CVE-2006-0398", value:TRUE);
   set_kb_item(name:"CVE-2006-0399", value:TRUE);
   set_kb_item(name:"CVE-2005-3319", value:TRUE);
   set_kb_item(name:"CVE-2005-3353", value:TRUE);
   set_kb_item(name:"CVE-2005-3391", value:TRUE);
   set_kb_item(name:"CVE-2005-3392", value:TRUE);
   set_kb_item(name:"CVE-2005-0384", value:TRUE);
   set_kb_item(name:"CVE-2006-0391", value:TRUE);
   set_kb_item(name:"CVE-2005-2713", value:TRUE);
   set_kb_item(name:"CVE-2005-2714", value:TRUE);
   set_kb_item(name:"CVE-2006-0386", value:TRUE);
   set_kb_item(name:"CVE-2006-0383", value:TRUE);
   set_kb_item(name:"CVE-2005-3706", value:TRUE);
   set_kb_item(name:"CVE-2006-0395", value:TRUE);
   set_kb_item(name:"CVE-2005-4217", value:TRUE);
   set_kb_item(name:"CVE-2005-3712", value:TRUE);
   set_kb_item(name:"CVE-2006-0390", value:TRUE);
   set_kb_item(name:"CVE-2006-4504", value:TRUE);
   set_kb_item(name:"CVE-2006-0387", value:TRUE);
   set_kb_item(name:"CVE-2006-0388", value:TRUE);
   set_kb_item(name:"CVE-2006-0848", value:TRUE);
   set_kb_item(name:"CVE-2006-0389", value:TRUE);
  }
  if (version < 5) {
   set_kb_item(name:"CVE-2006-0382", value:TRUE);
  }
  if (version < 4) {
   set_kb_item(name:"CVE-2005-2088", value:TRUE);
   set_kb_item(name:"CVE-2005-2700", value:TRUE);
   set_kb_item(name:"CVE-2005-2757", value:TRUE);
   set_kb_item(name:"CVE-2005-3185", value:TRUE);
   set_kb_item(name:"CVE-2005-3700", value:TRUE);
   set_kb_item(name:"CVE-2005-2969", value:TRUE);
   set_kb_item(name:"CVE-2005-3701", value:TRUE);
   set_kb_item(name:"CVE-2005-2491", value:TRUE);
   set_kb_item(name:"CVE-2005-3702", value:TRUE);
   set_kb_item(name:"CVE-2005-3703", value:TRUE);
   set_kb_item(name:"CVE-2005-3705", value:TRUE);
   set_kb_item(name:"CVE-2005-1993", value:TRUE);
   set_kb_item(name:"CVE-2005-3704", value:TRUE);
  }
  if (version < 3) {
   set_kb_item(name:"CVE-2005-2749", value:TRUE);
   set_kb_item(name:"CVE-2005-2750", value:TRUE);
   set_kb_item(name:"CVE-2005-2751", value:TRUE);
   set_kb_item(name:"CVE-2005-2739", value:TRUE);
   set_kb_item(name:"CVE-2005-1126", value:TRUE);
   set_kb_item(name:"CVE-2005-1406", value:TRUE);
   set_kb_item(name:"CVE-2005-2752", value:TRUE);
   set_kb_item(name:"CVE-2005-2747", value:TRUE);
   set_kb_item(name:"CVE-2005-2746", value:TRUE);
   set_kb_item(name:"CVE-2005-2745", value:TRUE);
   set_kb_item(name:"CVE-2005-2748", value:TRUE);
   set_kb_item(name:"CVE-2005-2744", value:TRUE);
   set_kb_item(name:"CVE-2005-2743", value:TRUE);
   set_kb_item(name:"CVE-2005-1992", value:TRUE);
   set_kb_item(name:"CVE-2005-2524", value:TRUE);
   set_kb_item(name:"CVE-2005-2742", value:TRUE);
   set_kb_item(name:"CVE-2005-2741", value:TRUE);
   set_kb_item(name:"CVE-2005-1344", value:TRUE);
   set_kb_item(name:"CVE-2004-0942", value:TRUE);
   set_kb_item(name:"CVE-2004-0885", value:TRUE);
   set_kb_item(name:"CVE-2004-1083", value:TRUE);
   set_kb_item(name:"CVE-2004-1084", value:TRUE);
   set_kb_item(name:"CVE-2005-2501", value:TRUE);
   set_kb_item(name:"CVE-2005-2502", value:TRUE);
   set_kb_item(name:"CVE-2005-2503", value:TRUE);
   set_kb_item(name:"CVE-2005-2504", value:TRUE);
   set_kb_item(name:"CVE-2005-2506", value:TRUE);
   set_kb_item(name:"CVE-2005-2525", value:TRUE);
   set_kb_item(name:"CVE-2005-2526", value:TRUE);
   set_kb_item(name:"CVE-2005-2507", value:TRUE);
   set_kb_item(name:"CVE-2005-2508", value:TRUE);
   set_kb_item(name:"CVE-2005-2519", value:TRUE);
   set_kb_item(name:"CVE-2005-2513", value:TRUE);
   set_kb_item(name:"CVE-2004-1189", value:TRUE);
   set_kb_item(name:"CVE-2005-1174", value:TRUE);
   set_kb_item(name:"CVE-2005-1175", value:TRUE);
   set_kb_item(name:"CVE-2005-2511", value:TRUE);
   set_kb_item(name:"CVE-2005-2509", value:TRUE);
   set_kb_item(name:"CVE-2005-2512", value:TRUE);
   set_kb_item(name:"CVE-2005-2745", value:TRUE);
   set_kb_item(name:"CVE-2005-0709", value:TRUE);
   set_kb_item(name:"CVE-2005-0710", value:TRUE);
   set_kb_item(name:"CVE-2005-0711", value:TRUE);
   set_kb_item(name:"CVE-2004-0079", value:TRUE);
   set_kb_item(name:"CVE-2004-0112", value:TRUE);
   set_kb_item(name:"CVE-2005-2515", value:TRUE);
   set_kb_item(name:"CVE-2005-2516", value:TRUE);
   set_kb_item(name:"CVE-2005-2517", value:TRUE);
   set_kb_item(name:"CVE-2005-2524", value:TRUE);
   set_kb_item(name:"CVE-2005-2520", value:TRUE);
   set_kb_item(name:"CVE-2005-2518", value:TRUE);
   set_kb_item(name:"CVE-2005-2510", value:TRUE);
   set_kb_item(name:"CVE-2005-1769", value:TRUE);
   set_kb_item(name:"CVE-2005-2095", value:TRUE);
   set_kb_item(name:"CVE-2005-2522", value:TRUE);
   set_kb_item(name:"CVE-2005-0605", value:TRUE);
   set_kb_item(name:"CVE-2005-2096", value:TRUE);
   set_kb_item(name:"CVE-2005-1849", value:TRUE);
  }
  if (version < 2) {
   set_kb_item(name:"CVE-2005-2194", value:TRUE);
   set_kb_item(name:"CVE-2005-1474", value:TRUE);
   set_kb_item(name:"CVE-2005-1721", value:TRUE);
   set_kb_item(name:"CVE-2005-1720", value:TRUE);
   set_kb_item(name:"CVE-2005-1333", value:TRUE);
   set_kb_item(name:"CVE-2005-1722", value:TRUE);
   set_kb_item(name:"CVE-2005-1726", value:TRUE);
   set_kb_item(name:"CVE-2005-1725", value:TRUE);
   set_kb_item(name:"CVE-2005-1723", value:TRUE);
   set_kb_item(name:"CVE-2005-1728", value:TRUE);
   set_kb_item(name:"CVE-2005-1724", value:TRUE);
   set_kb_item(name:"CVE-2005-0524", value:TRUE);
   set_kb_item(name:"CVE-2005-0525", value:TRUE);
   set_kb_item(name:"CVE-2005-1042", value:TRUE);
   set_kb_item(name:"CVE-2005-1043", value:TRUE);
   set_kb_item(name:"CVE-2005-1343", value:TRUE);
  }
  if (version < 1) {
   set_kb_item(name:"CVE-2005-1333", value:TRUE);
   set_kb_item(name:"CVE-2005-1474", value:TRUE);
   set_kb_item(name:"CVE-2005-1472", value:TRUE);
   set_kb_item(name:"CVE-2005-0974", value:TRUE);
   set_kb_item(name:"CVE-2005-1473", value:TRUE);
  }
 }
 if ("10.3." >< os) {
  report="The remote host is running Mac OS X 10.3.
As this version is no longer supported by Apple, 
please consider upgrading to the latest version.
";
  if ("10.3.9" >!< os) {                                                                               
   report+="Moreover, if you are planning on keeping this version, 
at least update it to the last one released - 10.3.9"; 
   }
  }
 if ("10.2." >< os) {
  report="The remote host is running Mac OS X 10.2.
As this version is no longer supported by Apple, 
please consider upgrading to the latest version.
";
  if ("10.2.8" >!< os) {                                                                               
   report+="Moreover, if you are planning on keeping this version, 
at least update it to the last one released - 10.2.8"; 
  } 
 }
 if ("10.1." >< os) {
  report="The remote host is running Mac OS X 10.1. 
As this version is no longer supported by Apple, 
please consider upgrading to the latest version.
";
  if ("10.1.5" >!< os) {
   report+="Moreover, if you are planning on keeping this version, 
at least update it to the last one released - 10.1.5";
  }
 }
}

if (report) security_note(data:report);
