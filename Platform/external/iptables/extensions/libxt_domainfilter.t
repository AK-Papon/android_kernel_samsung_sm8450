:OUTPUT,POSTROUTING
*filter
-j domainfilter --whitelist *uol.com;=;OK
-j domainfilter --whitelist *uol.com*;=;OK
-j domainfilter --whitelist uol.com*;=;OK
-j domainfilter --whitelist uol.com;=;OK
-j domainfilter --blacklist *uol.com;=;OK
-j domainfilter --blacklist *uol.com*;=;OK
-j domainfilter --blacklist uol.com*;=;OK
-j domainfilter --blacklist uol.com;=;OK
-j domainfilter;;FAIL