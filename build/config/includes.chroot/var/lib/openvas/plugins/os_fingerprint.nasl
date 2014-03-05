###################################################################
# OpenVAS Network Vulnerability Test
#
# OS Fingerprint
#
# LSS-NVT-2009-002
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
tag_summary = "This script performs ICMP based OS fingerprinting (as described by
Ofir Arkin and Fyodor Yarochkin in Phrack #57). It can be used to determine
remote operating system version.";

if (description) {
 script_id(102002);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-05-19 12:05:50 +0200 (Tue, 19 May 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("OS fingerprinting");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);


 script_summary("Detects remote operating system version");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("Copyright (C) 2009 LSS");
 script_xref(name : "URL" , value : "http://www.phrack.org/issues.html?issue=57&amp;id=7#article");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

if ( TARGET_IS_IPV6() ) exit(0);

ATTEMPTS = 2;
passed = 0;

include("host_details.inc");


# Fingerprints extracted from xprobe2.conf
# -----
# The fingerprints table is divided into sections. Each section starts with its
# label, followed by the corresponding fingerprints. An emty string closes the
# section.
# In case there are several matches for the remote OS, then the section title(s)
# will be displayed instead of the whole list of matches.

FINGERPRINTS = make_list(
    "AIX,cpe:/o:ibm:aix",
        "AIX 5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,y,!0,<255,y,0,1,!0,8,<255,0,BAD,OK,>20,OK",
        "AIX 4.3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,y,!0,<255,y,0,1,!0,8,<255,0,BAD,OK,>20,OK",
    "",
    "Apple Mac OS X,cpe:/o:apple:mac_os_x",
        "Apple Mac OS X 10.2.0,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.3,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.5,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.6,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.7,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.2.8,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.0,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.1,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.2,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.3,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.4,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.5,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.6,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.7,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.8,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.3.9,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.4.0,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "Apple Mac OS X 10.4.1,y,!0,!0,!0,1,<64,n,!0,<64,n,!0,<255,,,,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
    "",
    "Cisco IOS,cpe:/o:cisco:ios",
        "Cisco IOS 12.3,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 12.2,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 12.0,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.3,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0xc0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.2,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "Cisco IOS 11.1,y,!0,SENT,!0,1,<255,y,SENT,<255,n,SENT,<255,y,SENT,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
    "",
    "FreeBSD,cpe:/o:freebsd:freebsd",
        "FreeBSD 5.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.3,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.2.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.1,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 5.0,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.11,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.10,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.9,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.8,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.7,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.6.2,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.6,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.5,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.4,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,OK,OK,OK,OK",
        "FreeBSD 4.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.1.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,OK,OK,OK,OK",
        "FreeBSD 4.0,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 2.2.8,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
        "FreeBSD 2.2.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,BAD,FLIPPED,OK,FLIPPED",
    "",
    "HP UX,cpe:/o:hp:hp-ux",
        "HP UX 11.0x,y,!0,!0,!0,1,<255,n,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "HP UX 11.0,y,!0,!0,!0,1,<255,n,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
    "",
    "HP JetDirect,cpe:/h:hp:jetdirect",
        "HP JetDirect ROM A.03.17 EEPROM A.04.09,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM A.05.03 EEPROM A.05.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM F.08.01 EEPROM F.08.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM F.08.08 EEPROM F.08.05,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM F.08.08 EEPROM F.08.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.05.34 EEPROM G.05.35,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,0,OK,OK,OK",
        "HP JetDirect ROM G.06.00 EEPROM G.06.00,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.07.17,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.07.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.02 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.07.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.08.03,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.07.19 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.08.08 EEPROM G.08.04,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM G.08.21 EEPROM G.08.21,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM H.07.15 EEPROM H.08.20,y,0,!0,0,0,<60,n,!0,<60,n,!0,<60,n,!0,<60,y,0,0,!0,8,<60,OK,OK,OK,OK,OK",
        "HP JetDirect ROM L.20.07 EEPROM L.20.24,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,0,FLIPPED,OK,FLIPPED",
        "HP JetDirect ROM R.22.01 EEPROM L.24.08,y,!0,!0,!0,1,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0,1,!0,8,<64,0,0,FLIPPED,OK,FLIPPED",
    "",
    "Linux Kernel,cpe:/o:linux:kernel",
        "Linux Kernel 2.6.11,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.10,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.9,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.8,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.7,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.6,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.5,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.4,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.3,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.2,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.1,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.6.0,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.30,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.29,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.28,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.27,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.26,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.25,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.24,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.23,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.22,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.21,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.20,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.19,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.18,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.17,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.16,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.15,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.14,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.13,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.12,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.11,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.10,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.9,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.8,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.7,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.5,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.4 (I),y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.4,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.3,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.2,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.1,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.4.0,y,!0,0,!0,1,<255,y,0,<255,n,0,<255,n,0,<255,y,0xc0,1,0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.26,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.25,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.24,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.23,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.22,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.21,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.20,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.19,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.18,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.17,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.16,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.15,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.14,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.13,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.12,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.11,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.10,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.9,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.8,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.7,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.5,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.4,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.3,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.2,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.1,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.2.0,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0xc0,0,!0,>64,<255,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.36,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.34,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
        "Linux Kernel 2.0.30,y,!0,!0,!0,0,<64,y,!0,<64,n,!0,<64,n,!0,<64,y,0xc0,0,!0,>64,<64,OK,OK,OK,OK,OK",
    "",
    "Microsoft Windows,cpe:/o:microsoft:windows",
        "Microsoft Windows 2003 Server Enterprise Edition,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2003 Server Standard Edition,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP SP2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,>64,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP SP1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows XP,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 4,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 3,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server Service Pack 1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Server,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP4,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP3,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP2,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation SP1,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 2000 Workstation,y,0,!0,0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows Millennium Edition (ME),y,0,!0,!0,1,<128,y,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 6a,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 5,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 4,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 3,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 2,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server Service Pack 1,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Server,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 6a,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 5,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 4,y,0,!0,!0,1,<128,n,!0,<128,n,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 3,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 2,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation Service Pack 1,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows NT 4 Workstation,y,0,!0,!0,1,<128,n,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 98 Second Edition (SE),y,0,!0,!0,1,<128,y,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 98,y,0,!0,!0,1,<128,y,!0,<128,y,!0,<128,n,!0,<128,y,0,0,!0,8,<128,OK,OK,OK,OK,OK",
        "Microsoft Windows 95,y,0,!0,!0,1,<32,n,!0,<32,y,!0,<32,n,!0,<32,y,0,0,!0,8,<32,OK,OK,OK,OK,OK",
    "",
    "NetBSD,cpe:/o:netbsd:netbsd",
        "NetBSD 2.0,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6.2,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6.1,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.6,y,!0,!0,!0,0,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "NetBSD 1.3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
        "NetBSD 1.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
    "",
    "OpenBSD,cpe:/o:openbsd:openbsd",
        "OpenBSD 3.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.6,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 3.3,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.2,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.1,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 3.0,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,BAD,OK,<20,OK",
        "OpenBSD 2.9,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.8,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.7,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.6,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,<20,OK",
        "OpenBSD 2.5,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,0,!0,8,<255,OK,OK,OK,OK,OK",
        "OpenBSD 2.4,y,!0,!0,!0,1,<255,y,!0,<255,n,!0,<255,n,!0,<255,y,0,1,!0,8,<255,0,0,FLIPPED,OK,FLIPPED",
    "",
    "Sun Solaris,cpe:/o:sun:sunos",
        "Sun Solaris 10 (SunOS 5.10),y,!0,!0,!0,1,<255,n,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 9 (SunOS 5.9),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 8 (SunOS 2.8),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 7 (SunOS 2.7),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 6 (SunOS 2.6),y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
        "Sun Solaris 2.5.1,y,!0,!0,!0,1,<255,y,!0,<255,y,!0,<255,n,!0,<255,y,0,1,!0,64,<255,OK,OK,OK,OK,OK",
    ""
);


function _TTL(ttl) {
    if (ttl <= 32)       num = 32;
    else if (ttl <= 64)  num = 64;
    else if (ttl <= 128) num = 128;
    else                 num = 255;

    return "<" + num;
}


# ModuleA()
# 
#   ICMP Echo probe
#   Sends an ICMP Echo Request and generates a fingerprint from returned
#   packet's IP and ICMP headers.

function ModuleA() {
    ICMP_ECHO_REQUEST = 8;

    # We will set the IP_ID to constant number. Further more that number
    # needs to be symmetric so we can easily work around the NASL bug. 
    # The bug comes from get_ip_element() when we try to extract IP_ID 
    # field...the IP_ID field comes out flipped. For example: SENT 
    # IP_ID:0xAABB, extracted RECV IP_ID: 0xBBAA
   
    IP_ID = 0xBABA;  

    ICMP_ID = rand() % 65536;
    ip_packet =
        forge_ip_packet(ip_tos : 6,
                        ip_id  : IP_ID,
                        ip_off : IP_DF,        # DON'T FRAGMENT flag
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_ECHO_REQUEST,
                          icmp_code : 123,
                          icmp_seq  : 256,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);
    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {

        # pcap filter matches the ICMP Echo Reply packet with the same 
        # ID as the original Echo Request packet

        filter = "icmp and dst host " + this_host() +
                " and src host " + get_host_ip() +
                " and icmp[0] = 0" +
                 " and icmp[4:2] = " + ICMP_ID;

        ret = send_packet(icmp_packet, pcap_active : TRUE, 
                pcap_filter : filter, pcap_timeout : 1); 
    }

    # icmp_echo_reply
    # icmp_echo_code
    # icmp_echo_ip_id
    # icmp_echo_tos_bits
    # icmp_echo_df_bit
    # icmp_echo_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result = "y";

        if (get_icmp_element(element : "icmp_code", icmp : ret) == 0)
            result += ",0";
        else
            result += ",!0";
  
        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID) 
            result += ",SENT";
        else
            result += ",!0";

        if (get_ip_element(element : "ip_tos", ip : ret) == 0)
            result += ",0";
        else
            result += ",!0";

        if (get_ip_element(element : "ip_off", ip : ret) & IP_DF)
            result += ",1";
        else
            result += ",0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {

        # ICMP Echo Reply not received

        result = "n,,,,,";
    }

    return result;
}


# ModuleB()
# 
#   ICMP Timestamp probe
#   Sends an ICMP Timestamp packet and generates a fingerprint from returned
#   packet's (ICMP Timestamp Reply) IP and ICMP headers.

function ModuleB() {
    ICMP_TIMESTAMP = 13;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_TIMESTAMP,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1, 
            pcap_filter : 
                "icmp and dst host " + this_host() + 
                " and src host " + get_host_ip() +
                " and icmp[0] = 14" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_timestamp_reply
    # icmp_timestamp_reply_ip_id
    # icmp_timestamp_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";
 
        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {
        result += "n,,";
    }

    return result;
}


# ModuleC()
# 
#   ICMP Address Mask probe
#   Sends an ICMP Address Mask Request and generates a fingerprint from
#   returned packet's IP and ICMP headers.

function ModuleC() {
    ICMP_ADDRMASK = 17;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_ADDRMASK,
                          icmp_id   : ICMP_ID,
                          data      : crap(length:4, data:raw_string(0)),
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1, 
            pcap_filter : 
                "icmp and dst host " + this_host() + 
                " and src host " + get_host_ip() +
                " and icmp[0] = 18" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_addrmask_reply
    # icmp_addrmask_reply_ip_id
    # icmp_addrmask_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";

        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;
    } else {
        result += "n,,";
    }

    return result;
}


# ModuleD()
# 
#   ICMP Info Request probe

function ModuleD() {
    ICMP_INFOREQ = 15;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_ICMP,
                        ip_src : this_host());

    icmp_packet =
        forge_icmp_packet(icmp_type : ICMP_INFOREQ,
                          icmp_id   : ICMP_ID,
                          ip        : ip_packet);

    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        ret = send_packet(icmp_packet, pcap_active : TRUE, pcap_timeout : 1, 
            pcap_filter : 
                "icmp and dst host " + this_host() + 
                " and src host " + get_host_ip() +
                " and icmp[0] = 16" +
                " and icmp[4:2] = " + ICMP_ID);
    }

    # icmp_info_reply
    # icmp_info_reply_ip_id
    # icmp_info_reply_ttl

    result = "";
    if (ret) {
        passed = 1;
        result += "y";
 
        received_id = get_ip_element(element : "ip_id", ip : ret);
        if (received_id == 0)
            result += ",0";
        else if (received_id == IP_ID)
            result += ",SENT";
        else
            result += ",!0";

        ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ttl = _TTL(ttl);

        result += "," + ttl;

    } else {
        result = "n,,";
    }

    return result;
}


# ModuleE()
# 
#   ICMP Port Unreachable probe

function ModuleE() {
    ICMP_UNREACH_DEF_PORT = 65534;
    IP_ID = 0xBABA;
    ICMP_ID = rand() % 65536;

    ip_packet =
        forge_ip_packet(ip_id  : IP_ID,
                        ip_p   : IPPROTO_UDP,
                        ip_off : IP_DF,
                        ip_src : this_host());
    attempt = ATTEMPTS;
    ret = NULL;
    while (!ret && attempt--) {
        dport = ICMP_UNREACH_DEF_PORT - attempt;
        udp_packet =
            forge_udp_packet(
                                data     : crap(70),
                                ip       : ip_packet,
                                uh_dport : dport,
                                uh_sport : 53
                             );

        # ICMP Port Unreachable packet contains our sent packet
        ret = send_packet(udp_packet, pcap_active : TRUE, pcap_timeout : 1, 
            pcap_filter : 
                "icmp and dst host " + this_host() + 
                " and src host " + get_host_ip() +
                " and icmp[0] = 3" +
                " and icmp[1:1] = 3 " +
                " and icmp[30:2] = " + dport);

    }

    # icmp_unreach_reply
    # icmp_unreach_precedence_bits
    # icmp_unreach_df_bit
    # icmp_unreach_ip_id
    # icmp_unreach_echoed_dtsize
    # icmp_unreach_reply_ttl
    # icmp_unreach_echoed_udp_cksum
    # icmp_unreach_echoed_ip_cksum
    # icmp_unreach_echoed_ip_id
    # icmp_unreach_echoed_total_len
    # icmp_unreach_echoed_3bit_flags

    result = "";
    if (ret) {
        passed = 1;

        # IP_Header_of_the_UDP_Port_Unreachable_error_message

        result += "y";

        # icmp_unreach_precedence_bits = 0xc0, 0, (hex num)

        tos = get_ip_element(ip:ret, element:"ip_tos");
        if (tos == 0xc0)
            result += ",0xc0";
        else if (tos == 0)
            result += ",0";
        else
            result += ",!0";

        # icmp_unreach_df_bit = [0 , 1 ]
        # we cannont access only df bit or 3bitflags. we access 
        # 3_bit_flags + frag_offset

        _3bit_flag_frag_off = get_ip_element(ip:ret, element:"ip_off");	
        if (_3bit_flag_frag_off & IP_DF)
            result += ",1";
        else
            result += ",0";

        #icmp_unreach_ip_id = [0, !0, SENT]

        received_id = get_ip_element(ip:ret, element:"ip_id");
        if (received_id == IP_ID)
            result += ",SENT";
        else if (received_id == 0)
            result += ",0";
        else
            result += ",!0";

        #icmp_unreach_echoed_dtsize = [8, 64, >64]

        echoed_dtsize = get_ip_element(ip:ret, element:"ip_len") - 20;
        if (echoed_dtsize == 64)
            reslt += ",64";
        else if (echoed_dtsize > 64)
            result += ",>64";
        else if (echoed_dtsize == 8)
            result += ",8";
        else
            result += "," + echoed_dtsize;

        # Original_data_echoed_with_the_UDP_Port_Unreachable_error_message
        # we bypass the ip + icmp_unreach and we get to our original packet!

        hl = get_ip_element(ip:ret, element:"ip_hl");
        echoed_ip_packet = substr(ret, hl*4+8);
        echoed_ip_packet_hl = get_ip_element(ip:echoed_ip_packet, element:"ip_hl");
        echoed_udp_packet = substr(echoed_ip_packet, echoed_ip_packet_hl*4); 

        # icmp_unreach_reply_ttl = [>< decimal num] 

        reply_ttl = get_ip_element(element : "ip_ttl", ip : ret);
        ip_packet_ttl = get_ip_element(ip: ip_packet, element : "ip_ttl");
        echoed_ip_packet_ttl = get_ip_element(ip:echoed_ip_packet, element:"ip_ttl");
        real_ttl = reply_ttl + ip_packet_ttl - echoed_ip_packet_ttl ;

        if (real_ttl <= 32)
            result += ",<32";
        else if (real_ttl <= 60)
            result += ",<60";
        else if (real_ttl <= 64)
            result += ",<64";
        else if (real_ttl <= 128)
            result += ",<128";
        else
            result += ",<255";

        # Extracting checksums from echoed datagram 
        # icmp_unreach_echoed_udp_cksum = [0, OK, BAD]

        echoed_udp_checksum = get_udp_element(udp: echoed_udp_packet, element:"uh_sum");
        udp_packet_checksum = get_udp_element(udp: udp_packet, element: "uh_sum");

        if (echoed_udp_checksum == udp_packet_checksum)
            result += ",OK";
        else if (echoed_udp_checksum == 0)
            result += ",0";
        else
            result += ",BAD";

        # icmp_unreach_echoed_ip_cksum  = [0, OK, BAD]

        echoed_ip_checksum = get_ip_element(ip:echoed_ip_packet, element:"ip_sum");

        # making a copy of the original udp_packet with updated ttl field
        # to the echoed_ip_packet's ttl and then extracting ip checksum 
        # from udp_packet_copy

        ip_packet_copy = forge_ip_packet(ip_id  : IP_ID,
                            ip_p   : IPPROTO_UDP,
                            ip_off : IP_DF,
                            ip_src : this_host(),
                            ip_ttl : get_ip_element(ip:echoed_ip_packet, element:"ip_ttl"));
        udp_packet_copy =
            forge_udp_packet(
                                data     : crap(70),
                                ip       : ip_packet_copy,
                                uh_dport : dport,
                                uh_sport : 53
                             );

        ip_packet_copy_checksum = get_ip_element(ip:udp_packet_copy, element: "ip_sum");

        if (echoed_ip_checksum == ip_packet_copy_checksum)
            result += ",OK";
        else if (echoed_ip_checksum == 0)
            result += ",0";
        else
            result += ",BAD";

        # icmp_unreach_echoed_ip_id = [OK, FLIPPED]
        original_ip_id = substr(ip_packet, 4,5); 
        echoed_ip_id = substr(echoed_ip_packet, 4,5);
        # flipp the two bytes 
        flipped_original_ip_id = raw_string(substr(original_ip_id, 1), substr(original_ip_id, 0, 0));
        # end flipp 

        if (original_ip_id == echoed_ip_id)
            result += ",OK";
        else if (original_ip_id == flipped_original_ip_id)
            result += ",FLIPPED";
        else
            result += ",BAD";

        # icmp_unreach_echoed_total_len = [>20, OK, <20]

        echoed_total_len = get_ip_element(ip:echoed_ip_packet, element: "ip_len");
        original_total_len = get_ip_element(ip:udp_packet, element: "ip_len");

        if (echoed_total_len == original_total_len)
            result += ",OK";
        else if (echoed_total_len == original_total_len - 20)
            result += ",<20";
        else if (echoed_total_len == original_total_len + 20)
            result += ",>20";
        else
            result += ",unexpected";

        # icmp_unreach_echoed_3bit_flags = [OK, FLIPPED]

        echoed_ip_frag_off = get_ip_element(ip:echoed_ip_packet, element: "ip_off");
        original_ip_frag_off = get_ip_element(ip:ip_packet, element: "ip_off");

        # flipp the two bytes

        flipped_original_ip_frag_off = raw_string(substr(original_ip_frag_off, 1), substr(original_ip_frag_off, 0, 0));

        #end flipp

        if (echoed_ip_frag_off == original_ip_frag_off)
            result += ",OK";
        else if (echoed_ip_frag_off == flipped_original_ip_frag_off)
            result += ",FLIPPED";
        else
            result += ",unexpected";

    } else {
        result += "n,,,,,,,,,,";
    }

    return result;
}

#------------------------------------------------------------------------------

result = 
    ModuleA() + "," +
    ModuleB() + "," +
    ModuleC() + "," +
    ModuleD() + "," +
    ModuleE();

# display(result, '\n');

fp = split(result, sep:",", keep:0);

# iterate through fingerprints and find the best match

best_score     = 0;
best_os        = make_array();
store_sections = FALSE;

if (passed) {

    section_title = "";

    foreach line (FINGERPRINTS) {

        if (section_title == "") {
    	    extract = split(line, sep:",", keep:0);
    	    section_title = extract[0];
    	    section_cpe = extract[1];
    	    continue;
        } else if (line == "") {
    	    section_title = "";
    	    continue;
        } else {

            ar = split(line, sep:",", keep:0);

            name = ar[0];
            score = 0;
            total = 0;

            for (i = 0; i < max_index(fp); ++i) {
                # skip unset value
                if (isnull(fp[i]) || fp[i] == "")
                    continue;

                total += 1;

                if (!isnull(ar[i+1]) && ar[i+1] != "" && ar[i+1] == fp[i])
                    score += 1;
            }

            if (total > 0)
                percentage = 100*score/total;

            if (percentage > best_score) {
                best_score = percentage;
                best_os = make_array(name, section_cpe);
                store_sections = FALSE;
            } else if (percentage == best_score) {
                # In case we have several matches, then just use the section title
                if (!store_sections) {
                    best_os = make_array(section_title, section_cpe);
                    store_sections = TRUE;
                } else {
                    best_os[section_title] = section_cpe;
                }
            }
        }
    }
}

if (best_score == 0) {
    best_os = "Unknown";
    best_os_list = "Unable to detect remote OS. No match found.";
    dont_report = TRUE;
}

ostitle = '';
report = string('ICMP based OS fingerprint results: (', best_score, '% confidence)\n');

if( typeof( best_os ) == "array") { 

  foreach ostitle (keys(best_os)) {
      register_host_detail(name:"OS", value:ostitle, nvt:"1.3.6.1.4.1.25623.1.0.102002",
          desc:"Detects remote operating system version");

      register_host_detail(name:"OS", value:best_os[ostitle], nvt:"1.3.6.1.4.1.25623.1.0.102002",
          desc:"Detects remote operating system version");

      report = report + '\n' + ostitle;
  }
} else {

  report += string(best_os,"\n");

}  

set_kb_item(name:"Host/OS/ICMP", value:ostitle);
set_kb_item(name:"Host/OS/ICMP/Confidence", value:best_score);

if(!dont_report)
 log_message(data:report);

