# SPE

## Overview
SPE is a security testing tool for Linux platform x86 64-bit hosts to protect against kernel vulnerability exploits. Based on LKM to simulate some kernel exploits to avoid complex kernel exploit coding and debugging. A helper program for easy testing is also provided.

## Features
SPE provides the following security testing functions through the spe device:
+ 3 ways to elevate privileges
+ 2 basic types of container escape methods
+ 2 ways to tamper with read-only files
+ hijacking vdso to reverse shell
+ hijacking modprobe path

## Compatibility
Validated Versions:
+ 5.19.0-38-generic #39~22.04.1-Ubuntu
+ 5.4.0-47-generic #51-Ubuntu
+ 4.4.0-142-generic #168~14.04.1-Ubuntu

Stack failure only, not yet resolved:
+ 4.18.0-348.7.1.el8_5.x86_64 Centos 8.5 
+ 3.10.0-1160.71.1.el7.x86_64 Centos7.9

All similar versions should work.

## Installation
Compile
```
make
```
Load the module(as root)
```
insmod SPE.ko
```

## Usage
You can use the helper program directly for easy testing.
```
cd helper && make
```
Via `./speHelper --help` to start. 
```
Usage: speHelper [Command] [Opiton]...
A simple helper program for kernel exploit testing using SPE.

Available commands:
  privup    For privilege elevation.
  escape    For container escape.
  file      For modifying read-only file.
  vdso      For modifying vdso.
  modprobe  For modifying modprobe path.

Use 'speHelper [Command] --help' to get more information about the command.
```
Using SPE in a container environment requires adding spe device support. 
Take docker as an example:
```
docker run --device /dev/spe [OPTIONS] IMAGE [COMMAND] [ARG...]
```
The usage of the spe device can be found in the source code of the helper program. A more sound security test can be performed by rewriting the helper program, such as adding heap spray code.