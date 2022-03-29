# Insecure Corporate Proxy Trust

Dealing with proxies that mess up our trust. Proxy https traffic as well as http is common in gov and large corporate companies. Some Proxies also [man-in-the-middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) generating certificates on the fly. 

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

### urllib3 | python 

:anger: Insecure - Not Using Proxy Trust

```python
requests.packages.urllib3.disable_warnings()
```

:anger: Insecure - Not Using Proxy Trust

```python
import urllib3 urllib3.disable_warnings()
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

```ini
[http]
    proxy = http://proxy:port
[https]
    proxy = http://proxy:port
```

:anger: Insecure - Not Using Proxy Trust

`git config --global http.sslVerify false`

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


