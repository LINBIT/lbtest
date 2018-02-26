# lbtest

This repository contains a set of tools that are used to test various [LINBIT](https://www.linbit.com)
projects concurrently in many VMs efficiently.

This project consists of 3 parts:

## d2ch
This extracts a docker container to the file system, effectively generating a chroot.

## ch2vm
This in the end starts a VM based on a given distribution and kernel. It contains lots of nice magic that
layers ZFS snapshots in order to provide spearated per VM clones efficiently.

## vmshed
This basically takes as input two configuration files, one that defines the tests, and one that defines the
set of VMs. Then it executes tests concurrently and collects the result and if desired prepares output that
can be used in [jenkins](https://jenkins.io)

For more information please browse through the [presentation](https://go-talks.appspot.com/github.com/LINBIT/lbtest/lbtest.slide) or read it in [raw format](https://github.com/LINBIT/lbtest/blob/master/lbtest.slide)
