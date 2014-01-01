Malformity_Remote
=================

## 1.0 Introduction

This is a remote version of the local transform package Malformity. For organizations with a Maltego Transform Distribution Server (TDS), or who wish to use the public Paterva TDS, this implementation with simplify deployment and management of Malformity.

## 2.0 Installing Malformity_Remote

You will first need to follow the guides provided by Paterva [here](http://www.paterva.com/web6/documentation/TRX_documentation20130403.pdf) to set up a seed and server. 

Configuration notes and details for seed setup are included in the Malformity.py file for each transform. Note: When entering transforms in your seed that require an API Key, don't forget to create and add a property to those transforms titled 'apikey'.

Once complete, copy the files in the 'deploy' folder to /var/www/TRX/. If you have customized the existing TRX.wsgi file, copy the appropriate contents of the Malformity TRX.wsgi file in to your file.

If your seed is set up, restarting the Apache server should make the transforms accessible.

# Contact

[@digital4rensics](https://twitter.com/Digital4rensics) - www.digital4rensics.com - Keith@digital4rensics.com