# Insecure Corporate Proxy Trust

:lock: - The right way.  
:anger: - The bad way.  

Dealing with proxies that mess up our trust. Proxy https traffic as well as http is common in gov and large corporate companies. Some Proxies also [man-in-the-middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) generating certificates on the fly. 

**Note: Make Sure your Date & Time is correct. This is step #1. Too large of time drift will cause SSL to fail.**

## Fetching the Proxy CA PEM 

:lock: - Importing Trust

If you use the 'openssl' tool, this is one way to get extract the CA cert for a particular server:

`openssl s_client -showcerts -servername server -connect server:443 > cacert.pem`

type "quit", followed by the "ENTER" key

The certificate will have "BEGIN CERTIFICATE" and "END CERTIFICATE" markers.

Validate the PEM data
`openssl x509 -inform PEM -in certfile -text -out certdata` where certfile is the cert you extracted from logfile. Look in certdata.

If you want to trust the certificate, you can add it to your CA certificate store or use it stand-alone as described. Just remember that the security is no better than the way you obtained the certificate.

### Am I MitM proxied?

No - I don't see a MitM Proxy

```
$ openssl s_client -connect pypi.python.org:443
CONNECTED(00000003)
depth=1 /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 Extended Validation Server CA
verify error:num=20:unable to get local issuer certificate
verify return:0
---
Certificate chain
 0 s:/businessCategory=Private Organization/1.3.6.1.4.1.311.60.2.1.3=US/1.3.6.1.4.1.311.60.2.1.2=Delaware/serialNumber=3359300/street=16 Allen Rd/postalCode=03894-4801/C=US/ST=NH/L=Wolfeboro,/O=Python Software Foundation/CN=www.python.org
   i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 Extended Validation Server CA
 1 s:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 Extended Validation Server CA
   i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
```   

Yes - There is a MitM ZScaler Proxy

```
openssl s_client -connect pypi.python.org:443
CONNECTED(00000003)
depth=2 C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = Zscaler Intermediate Root CA (zscalerthree.net), emailAddress = support@zscaler.com
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=1 C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = "Zscaler Intermediate Root CA (zscalerthree.net) (t) "
verify return:1
depth=0 CN = www.python.org
verify return:1
---
Certificate chain
 0 s:CN = www.python.org
   i:C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = "Zscaler Intermediate Root CA (zscalerthree.net) (t) "
 1 s:C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = "Zscaler Intermediate Root CA (zscalerthree.net) (t) "
   i:C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = Zscaler Intermediate Root CA (zscalerthree.net), emailAddress = support@zscaler.com
 2 s:C = US, ST = California, O = Zscaler Inc., OU = Zscaler Inc., CN = Zscaler Intermediate Root CA (zscalerthree.net), emailAddress = support@zscaler.com
   i:C = US, ST = California, L = San Jose, O = Zscaler Inc., OU = Zscaler Inc., CN = Zscaler Root CA, emailAddress = support@zscaler.com
```   

### Is the Intermediate CA Trusted?

:anger: Insecure - Completely untrusted!

```
openssl s_client -connect pypi.python.org:443
[...]
Verification error: unable to get local issuer certificate
```

## Dealing with Internal Untrusted / Unconfigured WebSites

### Chrome

#### Bypass “Your connection is not private” Message

To proceed, simply choose the “Advanced” link, then choose “Proceed to <link> (unsafe)“.

Additionally the Advanced link may not be present

1. Prevent Warning
2. Click a blank section of the denial page.
3. Using your keyboard, type `thisisunsafe`. This will add the website to a safe list, where you might not be prompted again, but it will proceed from the page to the URL.

### Using Flags

In the Chrome address bar, type “chrome://flags/#allow-insecure-localhost“
Select the `Enable` link.

### Console Proxy Configuration

Ex: wget, git and almost every console application which connects to internet. This alone is *not* enough to trust the SSL MitM Proxy.

The ***Mess of linux ENV** for proxy configurations. Note Most HTTPS Proxies are a mirror of the HTTP proxy.

```shell
export HTTP_PROXY=http://proxy.example.com:80
export HTTPS_PROXY=$HTTP_PROXY

export NO_PROXY=127.0.0.1,169.254.169.254,localhost
export no_proxy=$NO_PROXY
export noProxy=$NO_PROXY
export noproxy=$NO_PROXY

export http_proxy=$HTTP_PROXY
export https_proxy=$HTTPS_PROXY

export ftp_proxy=http://<YOUR.FTP-PROXY.URL:PORT>
export socks_proxy=http://<YOUR.SOCKS-PROXY.URL:PORT>
export FTP_PROXY=$ftp_proxy
export SOCKS_PROXY=$socks_proxy
```

One-time Shell ENV

```
export http_proxy=http://DOMAIN\USERNAME:PASSWORD@SERVER:PORT/
export ftp_proxy=http://DOMAIN\USERNAME:PASSWORD@SERVER:PORT/
```

Configure in `.bashrc`

```
$ vi /etc/bash.bashrc
export http_proxy=http://DOMAIN\USERNAME:PASSWORD@SERVER:PORT/
export ftp_proxy=http://DOMAIN\USERNAME:PASSWORD@SERVER:PORT/
```

Configure in `/etc/environment`

```
$ vi /etc/environment
https_proxy="http://myproxy.server.com:8080/" 
ftp_proxy="http://myproxy.server.com:8080/" ...
```

### wget 

:anger: Insecure - Not Using Proxy Trust | ` wget --no-check-certificate https://...`

Configuration for perm solution

:anger: Insecure - Not Using Proxy Trust

`echo "check_certificate = off" >> ~/.wgetrc`

### curl 

:anger: Insecure - Not Using Proxy Trust

`curl -O --insecure --header 'Host: www.example.com' -I https://207.5.1.10/file.html`

-- OR --

:anger: Insecure - Not Using Proxy Trust

`curl -k --header 'Host: www.example.com' -I https://207.5.1.10/file.html`

Configuration for perm solution

:anger: Insecure - Not Using Proxy Trust

```
$ vi $HOME/.curlrc
insecure
ftp-pasv
```

:lock: Adding Cert for `curl`

```
curl --cacert /path/to/my/ca.pem https://url
curl --header 'Host: www.cyberciti.biz' --cacert /pth/to/my/ca.pem https://207.5.1.10/nixcraft.tar.gz
```

:lock: 

```
curl --proxy-cert ca.pem https://url
```

ref: https://curl.se/docs/sslcerts.html

## sudo | Special Shell Considerations

`sudo` does not pass environment variables. For that you can add to sudoers

```
$> vi /etc/sudoers.d/00-environment 
Defaults env_keep += "http_proxy https_proxy ftp_proxy"
```


## pip | python

pip3 in python3 can accept a configuration file. This file even works in venv (python3 version of virtualenv).

The key is to put the pip configuration into the correct location.

python3(venv) when created, you place the config into the venv folder's root. 
`$HOME/sandbox/projectx/bin/activate` - You would put the `pip.conf` in `$HOME/sandbox/projectx`

`pip.ini` (Windows) or `pip.conf` (linux/unix)

```
[global]
trusted-host = pypi.python.org
               pypi.org
               files.pythonhosted.org
```

:anger: Insecure - Not Using Proxy Trust |  You can attempt to one off with 

`pip install foomonkey config --global http.sslVerify false`

-- or --

`pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org <package_name>`

ref: https://stackoverflow.com/questions/25981703/pip-install-fails-with-connection-error-ssl-certificate-verify-failed-certi

:lock: - Trust the Intermediate Cert

```
pip config set global.cert path/to/ca-bundle.crt
pip config list
```

ref: https://stackoverflow.com/a/52961564/1569557

### urllib3 | python 

:anger: Insecure - Not Using Proxy Trust

```python
requests.packages.urllib3.disable_warnings()
```

:anger: Insecure - Not Using Proxy Trust

```python
import urllib3 urllib3.disable_warnings()
```

### ssl | python3

:lock: Proper import for OpenSSL

When looking at where SSL certificates are loaded, you can analyse these location

`$> python -c "import ssl; print(ssl.get_default_verify_paths())"`

Adding the MitM CA to one of these locations should do the trick

```
DefaultVerifyPaths(cafile=None, capath='/usr/lib/ssl/certs', openssl_cafile_env='SSL_CERT_FILE', openssl_cafile='/usr/lib/ssl/cert.pem', openssl_capath_env='SSL_CERT_DIR', openssl_capath='/usr/lib/ssl/certs')
```

## .gemrc | ruby

:anger: Insecure - Not Using Proxy Trust

```
http_proxy: http://proxy:port
:ssl_verify_mode: 0
```

### Gemfile | ruby

```gemfile
source "http://rubygems.org"
```

### certs | ruby

:lock: - Importing Trust

```shell
$> set SSL_CERT_FILE=C:\RailsInstaller\cacert.pem
```

ref: https://gist.github.com/fnichol/867550

## .npmrc | node

:anger: Insecure - Not Using Proxy Trust

```ini
registry=http://registry.npmjs.org/
proxy=http://proxy:port/
https-proxy=http://proxy:port/
strict-ssl=false
```

## .bowerrc | bower

:anger: Insecure - Not Using Proxy Trust

```json
{
    "proxy": "http://proxy:port",
    "https-proxy": "http://proxy:port",
    "strict-ssl": false
}
```

## yarn

:anger: Insecure - Not Using Proxy Trust

```
yarn config set strict-ssl false
```

## .gitconfig | git

:lock: - Importing Trust

```
git config --global http.sslVerify true
git config --global http.sslCAInfo path/to/ca-bundle.crt
```

```
$> git config — global http.proxy $HTTP_PROXY
$> git config — global https.proxy $HTTP_PROXY
```

-- or --

```ini
[http]
    proxy = http://proxy:port
[https]
    proxy = http://proxy:port
```

:anger: Insecure - Not Using Proxy Trust

`git config --global http.sslVerify false`

### git over SSH
This is an example, and one is packaged into the config that ships. Add the following to your `~/.ssh/config` file:

```
host github.com
     port 22
     user git
     ProxyCommand connect-proxy -S <YOUR.SSH-PROXY.URL:PORT> %h %p
````

## env system variables (windows)

```shell
setx /s HTTP_PROXY http://proxy:port/ /m
setx /s HTTPS_PROXY http://proxy:port/ /m
setx /s NO_PROXY .localhost,.domain.local /m
```

## settings.json | visual studio code

:anger: Insecure - Not Using Proxy Trust

```json
{
  "http.proxy": "http://proxy:port/",
  "http.proxyStrictSSL": false
}
```

## add certificate to keychain | java

:anger: Insecure - Not Using Proxy Trust

`keytool -importcert -file <cert file> -keystore <path to JRE installation>/lib/security/cacerts`


## apt | Ubuntu & Debian Distros

Explicit Proxy Settings

```
Acquire::http::Proxy "http://username:password@yourproxyaddress:proxyport";
Acquire::https::Proxy "http://username:password@yourproxyaddress:proxyport";
```

:anger: Insecure - Not Using Proxy Trust

A new file needs to added to `/etc/apt/apt.conf.d/` called `00-SSL-INSECURE`

```
// Do not verify peer certificate
Acquire::https::Verify-Peer "false";
// Do not verify that certificate name matches server name
Acquire::https::Verify-Host "false";
```


