#!/bin/bash
rm *.deb
equivs-build hackinglab-tools
git add * 
git commit -m "autogenerated: version bump"
git push
git push origin master

