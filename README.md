[![Go Report Card](https://goreportcard.com/badge/github.com/saeeddhqan/evine)](https://goreportcard.com/report/github.com/saeeddhqan/evine)
[![License](https://img.shields.io/github/license/saeeddhqan/evine?color=%234ac41c)](https://opensource.org/licenses/GPL-3.0)
[![Build Status](https://travis-ci.com/saeeddhqan/evine.svg?branch=master)](https://travis-ci.com/saeeddhqan/evine)
# Evine

Interactive CLI Web Crawler.

Evine is a simple, fast, and interactive web crawler and web scraper written in Golang.
Evine is useful for a wide range of purposes such as metadata and data extraction, data mining, reconnaissance and testing.

[![asciicast](https://asciinema.org/a/351624.svg)](https://asciinema.org/a/351624)

Follow the project on [Twitter](https://twitter.com/EvineProject).

If you like the project, give it a star. It forces me to develop the project!


## Install

### From Binary
Pre-build [binary releases](https://github.com/saeeddhqan/evine/releases) are also available(Suggested).
### From source
```
go get github.com/saeeddhqan/evine
"$GOPATH/bin/evine" -h
```
### From GitHub
```
git clone https://github.com/saeeddhqan/evine.git
cd evine
go build .
mv evine /usr/local/bin
evine --help
```

Note: golang 1.13.x required.

## Commands & Usage

Keybinding                              | Description
----------------------------------------|---------------------------------------
<kbd>Enter</kbd>                        | Run crawler (from URL view)
<kbd>Enter</kbd>                        | Display response (from Keys and Regex views)
<kbd>Tab</kbd>       					          | Next view
<kbd>Ctrl+Space</kbd>                   | Run crawler
<kbd>Ctrl+S</kbd>                       | Save response
<kbd>Ctrl+Z</kbd>                       | Quit
<kbd>Ctrl+R</kbd>                       | Restore to default values (from Options and Headers views)
<kbd>Ctrl+Q</kbd>                       | Close response save view (from Save view)

```bash
evine -h
```
It will displays help for the tool:

| flag | Description | Example |
|------|-------------|---------|
| -url | URL to crawl for | evine -url toscrape.com |
| -url-exclude string | Exclude URLs maching with this regex (default ".*")  | evine -url-exclude ?id= | 
| -domain-exclude string | Exclude in-scope domains to crawl. Separate with comma. default=root domain | evine -domain-exclude host1.tld,host2.tld | 
| -code-exclude string | Exclude HTTP status code with these codes. Separate whit '\|' (default ".*") | evine -code-exclude 200,201 | 
| -delay int  | Sleep between each request(Millisecond) | evine -delay 300 | 
| -depth | Scraper depth search level (default 1) | evine -depth 2 | 
| -thread int | The number of concurrent goroutines for resolving (default 5) | evine -thread 10 |
| -header | HTTP Header for each request(It should to separated fields by \n). | evine -header KEY: VALUE\nKEY1: VALUE1 | 
| -proxy string | Proxy by scheme://ip:port | evine -proxy http://1.1.1.1:8080 | 
| -scheme string | Set the scheme for the requests (default "https") | evine -scheme http | 
| -timeout int | Seconds to wait before timing out (default 10) | evine -timeout 15 | 
| -query string | JQuery expression(It could be a file extension(pdf), a key query(url,script,css,..) or a jquery selector($("a[class='hdr']).attr('hdr')"))) | evine -query url,pdf,txt |
| -regex string | Search the Regular Expression on the page contents | evine -regex 'User.+' |
| -logger string | Log errors in a file | evine -logger log.txt | 
| -max-regex int | Max result of regex search for regex field (default 1000) | evine -max-regex -1 | 
| -robots | Scrape robots.txt for URLs and using them as seeds | evine -robots |
| -sitemap | Scrape sitemap.xml for URLs and using them as seeds | evine -sitemap |
| -wayback | Scrape WayBackURLs(web.archive.org) for URLs and using them as seeds | evine -sitemap |

### VIEWS
- <b>URL,</b> In this view, you should enter the URL string.
- <b>Options,</b> This view is for setting options.
- <b>Headers,</b> This view is for setting the HTTP Headers.
- <b>Query,</b> This view is used after the crawling web. 
  It will be used to extract the data(docs, URLs, etc) from the web pages that have been crawled.
- <b>Regex,</b> This view is useful to search the Regexes in web pages that have been crawled. Write your Regex in this view and press <kbd>Enter</kbd>.
- <b>Response,</b> All of the results writes in this view.
- <b>Search,</b> This view is used to search the Regexes in the Response view content.

### Extract methods
#### From Keys
Keys are predefined keywords that can be used to specify data like in scope URLs, out scope URLs, emails, etc.
List of all keys:
- <i>url,</i> to extract IN SCOPE urls. the urls completly are sanitized.
- <i>email,</i> to extract IN SCOPE and out scope emails.
- <i>query_urls,</i> to extract IN SCOPE urls that contains the get query: ?foo=bar.
- <i>all_urls,</i> to extract OUT SCOPE urls.
- <i>phone,</i> to extract a[href]s that contains a phone number.
- <i>media,</i> to extract files that are not web executable file. like .exe,.bat,.tar.xz,.zip, etc addresses.
- <i>css,</i> to extract CSS files.
- <i>script,</i> to extract JavaScript files.
- <i>cdn,</i> to extract Content Delivery Networks(CDNs) addresses. like //api.foo.bar/jquery.min.js
- <i>comment,</i> to extract html comments, <\!-- .* !-->
- <i>dns,</i> to extract subdomains that belongs to the website.
- <i>network,</i> to extract social network IDs. like facebook, twitter, etc.
- <i>all,</i> to extract all list of keys.(url,query_url,..)
keys are case-sensitive. Also, it could be written to or three key with comma separation.
#### From Extensions
Maybe you wanna a file that is not defined in keys. What can you do? You can easily write the extension of the file on the Query view. like png,xml,txt,docx,xlsx,a,mp3, etc.
#### From JQuery selector
If you have basic JQuery skills, you can easily use this feature, but if not, it is not very difficult. To have a quick view about the selectors [w3schools](https://www.w3schools.com/jquery/jquery_ref_selectors.asp) is a great source.<br>
example(To find source[src]):
```javascript
$("source").attr("src") // To find all of source[src] urls
$("h1").text() // To find h1 values
```
Template:
```javascript
$("SELECTOR").METHOD_NAME("arg")
```
It does not support queries like below:
```javascript
$('SELECTOR').METHOD("arg")
$('SELECTOR').METHOD('arg')
$("SELECTOR"  ).METHOD("arg" )
```
Methods are described below:
- <i>text(),</i> to returns the content of the SELECTOR without html tag.
- <i>html(),</i> to returns the content of the SELECTOR with html tag.
- <i>attr("ATTR"),</i> to get the attribute of the SELECTOR. e.g $("a").attr("href")




## Bugs or Suggestions

To report bugs or suggestions, create an [issue](https://github.com/saeeddhqan/evine/issues).

Evine is heavily inspired by [wuzz](https://github.com/asciimoo/wuzz).
