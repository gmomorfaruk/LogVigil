# Phishing Test URLs

## Safe
https://google.com
https://google.com/search?q=weather
https://totally-safe.com/about

## No HTTPS
http://google.com
http://google.com/login

## Typosquatting
http://goog1e.com/verify-account
http://paypa1.com/banking
http://faceb00k.com/login
https://goog1e.com

## IP Address URLs
http://192.168.1.100/login
http://192.168.1.1/login
https://192.0.2.10/dashboard

## URL Spoofing (@)
https://example.com@192.0.2.10/login
http://google.com@10.0.0.1/verify

## Blacklisted
https://securevault-update.com/login
http://malicious-site.com/payload
https://phish-portal.net/verify

## Worst Case
http://192.168.1.1/malicious-phish-login
http://goog1e.com@10.0.0.1/banking-verify
