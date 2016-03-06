#BlackBox security framework 
##based on [DynamoRIO](https://github.com/DynamoRIO/dynamorio)

BlackBox is implemented as a DynamoRIO client that requires a `SECURITY_AUDIT` extension to the DynamoRIO core. The repository your are now viewing is a fork of DynamoRIO containing the audit extension under cmake parameter 

    -DSECURITY_AUDIT=ON
    
To build BlackBox, simply follow the instructions for [building DynamoRIO](https://github.com/DynamoRIO/dynamorio/wiki/How-To-Build), and include the audit cmake parameter. The client is aptly named `blackbox` and will be found in the directory 

    clients/lib32/<target>/blackbox.dll

Note that BlackBox currently only runs on 32-bit Windows 7 (minor changes will be required for other 32-bit versions of Windows, significant changes for x64 Windows, and a major port is required to run in Linux on either x86 or ARM). 

To run a program in BlackBox, just follow the directions for [running programs in DynamoRIO](http://dynamorio.org/docs/page_deploy.html).

The supporting tools and scripts for BlackBox will be made available in another [uci-plrg](https://github.com/uci-plrg) repository soon.

