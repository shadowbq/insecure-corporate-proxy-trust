# Insecure Corporate Proxy Trust

:lock: - The right way. Trust the proxy.  
:anger: - The bad way. Skip Trusts.   

Dealing with proxies that mess up our trust requires configuration to keep things `secure`. Policies that require proxy https traffic, as well as http is common in government and large corporate companies. Some proxies also [man-in-the-middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) the secure connection generating new certificates on the fly. 

All to often the internet provides ':anger: - The bad way' to shortcut these policies, but not breaking trust ':lock: - The right way' should be our solution even if it means using these MITM certificates. 

**Note: Make Sure your Date & Time is correct. This is step #1. Too large of time drift will cause SSL to fail.**

- [Insecure Corporate Proxy Trust](#insecure-corporate-proxy-trust)
  - [Fetching the Proxy CA PEM](#fetching-the-proxy-ca-pem)
    - [I need a CRT not a CER (DER)](#i-need-a-crt-not-a-cer-der)
    - [Am I MitM proxied?](#am-i-mitm-proxied)
    - [Is the Intermediate CA Trusted?](#is-the-intermediate-ca-trusted)
  - [Browser Trusts](#browser-trusts)
    - [Proxy Configurations](#proxy-configurations)
    - [Firefox](#firefox)
    - [Chrome](#chrome)
    - [Console Proxy Configuration](#console-proxy-configuration)
    - [wget](#wget)
    - [curl](#curl)
  - [sudo | Special Shell Considerations](#sudo--special-shell-considerations)
  - [pip | python](#pip--python)
    - [urllib3 | python](#urllib3--python)
    - [ssl | python3](#ssl--python3)
  - [.gemrc | ruby](#gemrc--ruby)
    - [Gemfile | ruby](#gemfile--ruby)
    - [certs | ruby](#certs--ruby)
  - [javascript](#javascript)
    - [.npmrc | node - npm js pkg manager](#npmrc--node---npm-js-pkg-manager)
    - [.bowerrc | bower - deprecated](#bowerrc--bower---deprecated)
    - [yarn | yarn superset js npm pkg manager](#yarn--yarn-superset-js-npm-pkg-manager)
  - [.gitconfig | git](#gitconfig--git)
    - [git over SSH](#git-over-ssh)
  - [settings.json | visual studio code](#settingsjson--visual-studio-code)
  - [java | keytool](#java--keytool)
  - [Operating System](#operating-system)
    - [Ubuntu & Debian Distros](#ubuntu--debian-distros)
    - [Redhat | Enterprise Linux (EL)](#redhat--enterprise-linux-el)
    - [MacOS](#macos)
    - [Windows](#windows)
  - [Cloud CLIs](#cloud-clis)
    - [aws | Amazon CLI tool](#aws--amazon-cli-tool)
    - [gcloud | Google Cloud CLI tool](#gcloud--google-cloud-cli-tool)

## Fetching the Proxy CA PEM 

:lock: - Importing Trust

If you use the 'openssl' tool, this is one way to get extract the CA cert for a particular server:

`openssl s_client -showcerts -servername server -connect server:443 > cacert.pem`

type "quit", followed by the "ENTER" key

The certificate will have "BEGIN CERTIFICATE" and "END CERTIFICATE" markers.

Validate the PEM data
`openssl x509 -inform PEM -in certfile -text -out certdata` where certfile is the cert you extracted from logfile. Look in certdata.

If you want to trust the certificate, you can add it to your CA certificate store or use it stand-alone as described. Just remember that the security is no better than the way you obtained the certificate.

### I need a CRT not a CER (DER)

(Maybe you exported the CER/DER from a Keychain) 

Convert the certificate from CER to CRT using openssl 

```
openssl x509 -inform DER -in ZscalerRootCertificate-2048-SHA256.cer -out ZscalerRootCertificate-2048-SHA256.crt
```

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

## Browser Trusts

### Proxy Configurations

A corporate configuration should be modifying the system proxy to talk to a `.pac` file.

PAC files can be found via Autodiscovery (WPAD), Static Locations, or even be pushed via a local client (like a zscaler agent).

`http://127.0.0.1:9000/systemproxy-XXXXXX.pac`

```javascript
function FindProxyForURL(url, host) {

 /* WebSockets go directly */
    if (shExpMatch(url, "ws*://*.zzzz.com*") ||
    shExpMatch(url, "ws*://yyyy.com:9001*"))
        return "DIRECT";
    
  /* Local IP matching etc.. */  
    if (isInNet(myIpAddress(), "192.168.0.0", "255.255.255.0"))
    {
      return "PROXY proxy1.mydomain.local:8080";
    }
    
	 /* Corporate bypasses  */
    if (shExpMatch(host, "aaa.net") ||
    shExpMatch(host, "bbb.net") ||
    shExpMatch(host, "ccc.com") ||
    shExpMatch(host, "*.ddd.com")) 
    return "PROXY 127.0.0.1:9000";

// Default traffic forwarding.

    return "DIRECT";
}
```

#### WPAD Domains

The configuration’s file location can be published by using two alternative methods: DNS or DHCP. A web browser configured for WPAD, before fetching its first page sends a DHCPINFORM query to its local DHCP server in order to get the URL of the configuration file in the DHCP reply. If DHCP does not provide the desired information, the web browser will try to fetch the configuration file by using DNS resolution. For example if the FQDN of the client computer is computer.subdomain.domain.local, the web browser will try to fetch the configuration file from the following locations:

```c#
http://wpad.subdomain.domain.local/wpad.dat
http://wpad.domain.local/wpad.dat (some web browsers)
http://wpad.com/wpad.dat (in incorrect implementations)
```

### Firefox

Accept and do not change corporate configurations.

If you need to add the Certifcate manually (aka VM, non-enrolled machine) go to `Preferences -> Privacy & Security -> Certificates -> View Certificates -> Import`. Select the file with your certificate (`ZscalerRootCertificate-2048-SHA256.crt`), choose `Authorities`.

### Chrome

Accept and do not change corporate configurations. Non-enrolled machines that have blocks, require system import of SSL trust. Chrome does not use it's own CA system like Firefox.

#### Bypass “Your connection is not private” Message

To proceed, simply choose the “Advanced” link, then choose “Proceed to <link> (unsafe)“.

Additionally the Advanced link may not be present

1. Prevent Warning
2. Click a blank section of the denial page.
3. Using your keyboard, type `thisisunsafe`. This will add the website to a safe list, where you might not be prompted again, but it will proceed from the page to the URL.

#### Using Flags

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

:lock: Adding Cert for `curl`

`wget --ca-certificate=/etc/ssl/cert.pem https://...`

:anger: Insecure - Not Using Proxy Trust

`wget --no-check-certificate https://...`

#### `~/.wgetrc` Configuration

:lock: Adding Cert for `curl`

`ca_certificate = /etc/ssl/cert.pem`

:anger: Insecure - Not Using Proxy Trust

`echo "check_certificate = off" >> ~/.wgetrc`



### curl 

:lock: Adding Cert for `curl`

```
curl --cacert /path/to/my/ca.pem https://..
curl --header 'Host: www.cyberciti.biz' --cacert /pth/to/my/ca.pem https://207.5.1.10/nixcraft.tar.gz
```

:lock: Modern CA switch for curl to trust proxy

```
curl --proxy-cert ca.pem https://url
```

:anger: Insecure - Not Using Proxy Trust

`curl -O --insecure --header 'Host: www.example.com' -I https://207.5.1.10/file.html`

:anger: Insecure - Not Using Proxy Trust

`curl -k --header 'Host: www.example.com' -I https://207.5.1.10/file.html`


#### `.curlrc` Configuration

:lock: Adding Cert for `curl`

```
$ vi $HOME/.curlrc
cacert /path/to/my/ca.pem
ftp-pasv
```

:anger: Insecure - Not Using Proxy Trust

```
$ vi $HOME/.curlrc
insecure
ftp-pasv
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


:lock: - Trust the Intermediate Cert

```
pip config set global.cert path/to/ca-bundle.crt
pip config list
```

ref: https://stackoverflow.com/a/52961564/1569557

:anger: Insecure - Not Using Proxy Trust |  You can attempt to one off with 

`pip install foomonkey config --global http.sslVerify false`

-- or --

`pip.ini` (Windows) or `pip.conf` (linux/unix)

:anger: Insecure - Explicitly skipping these domains

```
[global]
trusted-host = pypi.python.org
               pypi.org
               files.pythonhosted.org
```

:anger: Insecure - Explicitly skipping these domains

`pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org <package_name>`

ref: https://stackoverflow.com/questions/25981703/pip-install-fails-with-connection-error-ssl-certificate-verify-failed-certi


### urllib3 | python 

Don't do this ever..

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

Possibly lib `requests` may not pickit up and you may need to add `ENV:REQUESTS_CA_BUNDLE`

```
export REQUESTS_CA_BUNDLE=/etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt
```

## .gemrc | ruby

:lock: - Importing Trust

Using a `.bundle` config

`bundle config ssl_ca_cert ./config/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt`

:anger: Insecure - Not Using Proxy Trust

```
http_proxy: http://proxy:port
:ssl_verify_mode: 0
```

### Gemfile | ruby

```gemfile
source "http://rubygems.org"
```

```
$> gem list rails --remote --all

*** REMOTE GEMS ***

ERROR:  SSL verification error at depth 2: unable to get local issuer certificate (20)
ERROR:  You must add /C=US/ST=California/L=San Jose/O=Zscaler Inc./OU=Zscaler Inc./CN=Zscaler Root CA/emailAddress=support@zscaler.com to your local trusted store
```

### certs | ruby

:lock: - Importing Trust

```shell
$> export SSL_CERT_FILE=/etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt
```

ref: https://gist.github.com/fnichol/867550

## javascript

### .npmrc | node - npm js pkg manager

:lock: - Importing Trust

```shell
npm config set cafile /etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt
```

You can see the configuration file

```ini
global.cert=/etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt
```

:anger: Insecure - Not Using Proxy Trust

```ini
registry=http://registry.npmjs.org/
proxy=http://proxy:port/
https-proxy=http://proxy:port/
strict-ssl=false
```

### .bowerrc | bower - deprecated 

...psst! While Bower is maintained, bower recommends using Yarn and Webpack or Parcel 

:lock: - Importing Trust

```json
{
    "proxy": "http://proxy:port",
    "https-proxy": "http://proxy:port",
    "ca": "/path/to/cacert.pem",
    "strict-ssl": true
}
```

:anger: Insecure - Not Using Proxy Trust

```json
{
    "proxy": "http://proxy:port",
    "https-proxy": "http://proxy:port",
    "strict-ssl": false
}
```

### yarn | yarn superset js npm pkg manager

```
  Error: unable to get local issuer certificate
      at TLSSocket.onConnectSecure (node:_tls_wrap:1518:34)
      at TLSSocket.emit (node:events:376:20)
      at TLSSocket._finishInit (node:_tls_wrap:942:8)
      at TLSWrap.ssl.onhandshakedone (node:_tls_wrap:716:12)
```      

:lock: - Importing Trust

```
yarn config set cafile /etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt
```

:anger: Insecure - Not Using Proxy Trust

```
yarn config set strict-ssl false
```

```
yarn config set "strict-ssl" false -g
```

.yarnrc
```
cafile null
strict-ssl false
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


## settings.json | visual studio code

:lock: - Importing Trust

* Ensure certificates are installed and trusted in the OS System.
* VScode settings, Application, Proxy, and UNCHECK the "System certificates" option. 
* Restart vscode and RE-CHECK it. 
* Restart again, and it works.

(Code snippet, VS doesnt have its own override)

`https://github.com/microsoft/vscode/blob/main/src/vs/platform/request/common/request.ts`

```ts
  'http.systemCertificates': {
    type: 'boolean',
    default: true,
    description: localize('systemCertificates', "Controls whether CA certificates should be loaded from the OS. (On Windows and macOS, a reload of the window is required after turning this off.)"),
    restricted: true
  }
```      

:anger: Insecure - Not Using Proxy Trust

```json
{
  "http.proxy": "http://proxy:port/",
  "http.proxyStrictSSL": false
}
```

## java | keytool 

Java and Gradle packages use keytool and keystores.

:lock: - Importing Trust

`keytool -importcert -file /etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt -keystore <path to JRE installation>/lib/security/cacerts`

Alternative flags

`keytool -import -trustcacerts -alias ZscalerRootCertificate-2048-SHA256 -file /etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt -keystore <path to JRE installation>/lib/security/cacerts`


## Operating System 

### Ubuntu & Debian Distros


:lock: - Importing Trust

Import the Certificate into the system trust of Ubuntu

```shell
cp /etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt /usr/local/share/ca-certificates
chmod 644 /usr/local/share/ca-certificates/ZscalerRootCertificate-2048-SHA256.crt
sudo update-ca-certificates
```

#### apt

:lock: - Importing Trust

A new file needs to added to `/etc/apt/apt.conf.d/` called `00-SSL-PROXIED`

```
Acquire {
  HTTP::proxy "http://username:password@yourproxyaddress:proxyport";
  HTTPS::proxy "http://username:password@yourproxyaddress:proxyport";
  HTTPS::Verify-Peer "true";
  CAInfo "/path/to/ca/certs.pem";
}
```

:anger: Insecure - Not Using Proxy Trust

A new file needs to added to `/etc/apt/apt.conf.d/` called `00-SSL-INSECURE`

```
// Do not verify peer certificate
Acquire::https::Verify-Peer "false";
// Do not verify that certificate name matches server name
Acquire::https::Verify-Host "false";
```

### Redhat | Enterprise Linux (EL)

:lock: - Importing Trust

Enable the dynamic CA configuration feature: 

```
sudo yum install ca-certificates
sudo update-ca-trust force-enable
sudo cp ca-certificates/ZscalerRootCertificate-2048-SHA256.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust extract
```

### MacOS

:lock: - Importing Trust

```
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/ZscalerRootCertificate-2048-SHA256.crt
```

### Windows

:lock: - Importing Trust

```
certutil -addstore -f "ROOT" ZscalerRootCertificate-2048-SHA256.crt
```

#### ENV Variables

Setting CLI ENV proxies for Windows (git, etc.)

```shell
setx /s HTTP_PROXY http://proxy:port/ /m
setx /s HTTPS_PROXY http://proxy:port/ /m
setx /s NO_PROXY .localhost,.domain.local /m
```


## Cloud CLIs 

### aws | Amazon CLI tool

:lock: - Importing Trust

```
export AWS_CA_BUNDLE=~/Documents/Zscaler\ Root\ CA.pem
```

-or- 

:lock: - Importing Trust

Run the `aws` command in terminal to configure the certificate

```
aws configure set ca_bundle /etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt
```

:anger: - Skip SSL

```
aws --no-verify-ssl s3 cp filename s3://bucketname/
```

### gcloud | Google Cloud CLI tool

:lock: - Importing Trust

Absolute path to a custom CA cert file.

```
gcloud config set core/custom_ca_certs_file  /etc/ssl/ca_root_certs/ZscalerRootCertificate-2048-SHA256.crt
gcloud config set auth/disable_ssl_validation False
```

If you need the explict proxy (`http, http_no_tunnel, socks4, socks5`)

```
gcloud config set proxy/type http
gcloud config set proxy/address 1.234.56.78
gcloud config set proxy/port 8080

```

:anger: - Skip SSL 

```
gcloud config set auth/disable_ssl_validation True
```

ref: https://cloud.google.com/sdk/gcloud/reference/config/set
