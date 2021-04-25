/* Evine, Copyright 2020.
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/jroimartin/gocui"
)

// Metadata
var VERSION = "0.1.3"
var STATUS_LINE_NAME = fmt.Sprintf("[evine/v%s]", VERSION)

// Options structure
type Options struct {
	Robots            bool
	Sitemap           bool
	WayBack           bool
	IgnoreInvalidSSL  bool
	Thread            int
	Timeout           int
	Delay             int
	Depth             int
	MaxRegexResult    int
	URL               string
	Proxy             string
	RegexString       string
	Logger       string
	Regex             *regexp.Regexp
	URLExclude        string
	URLExcludeRegex   *regexp.Regexp
	StatusCodeExclude string
	StatusCodeRegex   *regexp.Regexp
	InScopeExclude    string
	Scheme            string
	Headers           string
	Query             string
	Keys              []string
	InScopeDomains    []string
}

// Output result structure
type Results struct {
	Pages        string
	PageByURL    map[string]string
	URLs         map[string]bool
	OutScopeURLs map[string]bool
	QueryURLs    map[string]bool
	CSS          map[string]bool
	Scripts      map[string]bool
	CDNs         map[string]bool
	Medias       map[string]bool
	Emails       map[string]bool
	Phones       map[string]bool
	Networks     map[string]bool
	Comments     map[string]bool
	HostNames    []string
	RegMaches    map[string][]string
}

// Program definitions
type def struct {
	currentPage      string
	currentPageIndex int
	Gui              *gocui.Gui
}

// CUI View Attributes
type viewAttrs struct {
	editor   gocui.Editor
	editable bool
	frame    bool
	text     string
	title    string
	wrap     bool
	x0       func(int) int
	y0       func(int) int
	x1       func(int) int
	y1       func(int) int
}

// Search prompt editor struct type
type searchEditor struct {
	editor gocui.Editor
}

// URL editor struct type
type singleLineEditor struct {
	editor gocui.Editor
}

// RESPONSE editor struct type
type responseEditor struct {
	editor gocui.Editor
}

type errorString struct {
    s string
}

func (e *errorString) Error() string {
    return e.s
}

var (
	// Initial OPTIONS
	OPTIONS = &Options{}
	// To identify media postfixes
	MEDIA_POSTFIX = []string{"aa", "aac", "aif", "aiff", "amr", "amv", "amz", "ape", "asc", "asf", "au", "bash", "bat", "bmp", "c",
		"cfa", "chm", "cpp", "cs", "csv", "doc", "docx", "dmg", "f4a", "f4b", "f4p", "f4v", "flac", "flv", "gif", "gif", "gifv",
		"go", "gz", "ico", "java", "jfif", "jpeg", "jpg", "m2v", "m4a", "m4p", "m4v", "md", "mkv", "mng", "mov",
		"mp2", "mp3", "mp4", "mpeg", "mpg", "mpv", "msi", "pdf", "pl", "png", "ppt", "pptx", "py", "rar", "rm", "roq",
		"svg", "svi", "tar.gz", "tiff", "vmo", "vob", "w64", "wav", "webm", "wma", "wmv", "woff2", "wrk",
		"wvavi", "xlsx", "xz", "yaml", "yml", "zip", "7z", "tgz", "exe", "psd"}
	// Scheme://hostname.tld
	BASEURL = ""
	// Project Name: Hostname.tld
	PROJECT_NAME = ""
	VIEWS        = []string{"URL", "OPTIONS", "HEADERS", "QUERY", "REGEX", "RESPONSE", "SEARCH_PROMPT"}
	ALL_VIEWS    = []string{"URL", "OPTIONS", "HEADERS", "QUERY", "REGEX", "RESPONSE", "SEARCH", "STATUS_LINE", "SEARCH_PROMPT"}
	// Pre-define keys
	ALL_KEYS    = []string{"email", "url", "query_urls", "all_urls", "phone", "media", "css", "script", "cdn", "comment", "dns", "network", "all"}
	ERRORS_STACK= []string{}
	MIN_X       = 60
	MIN_Y       = 20
	VIEWS_OBJ   map[string]*gocui.View
	VIEWS_ATTRS = map[string]viewAttrs{}
	PROG        def
	DEPTH       = 1
	TOKENS      chan struct{}
	RESULTS     *Results
	START_TIME  time.Time
	MUTEX       = &sync.Mutex{}
	LOGGER_FILE *os.File
	LOGGER_FILE_FLAG = 0
)

// Find comments with regex
func findComments() {
	reg := regexp.MustCompile(`<!--.*?-->`)
	for _, v := range reg.FindAllString(RESULTS.Pages, -1) {
		if !RESULTS.Comments[v] {
			RESULTS.Comments[v] = true
		}
	}
}

// Find emails with regex
func findEmails() {
	reg := regexp.MustCompile(`[A-z0-9.\-_]+@[A-z0-9\-\.]{0,255}?` + PROJECT_NAME + `(?:[A-z]+)?`)
	founds := reg.FindAllString(RESULTS.Pages, -1)
	reg = regexp.MustCompile(`[A-z0-9.\-_]+@[A-z0-9\-.]+\.[A-z]{1,10}`)
	for _, v := range reg.FindAllString(RESULTS.Pages, -1) {
		if strings.Contains(strings.Split(v, "@")[1], ".") {
			founds = append(founds, strings.ToLower(v))
		}
	}
	for _, v := range founds {
		v = strings.ToLower(v)
		if !RESULTS.Emails[v] && toBool(v) {
			RESULTS.Emails[v] = true
		}
	}
}

// Find project DNS names with regex
func findHostnames() {
	reg := regexp.MustCompile(`[A-z0-9\.\-%]+\.` + PROJECT_NAME)
	for _, v := range reg.FindAllString(RESULTS.Pages, -1) {
		uniq(&RESULTS.HostNames, v)
	}
}

// Find social networks with regex
func findNetworks() {
	netexp := `(instagram\.com\/[A-z_0-9.\-]{1,30})|(facebook\.com\/[A-z_0-9\-]{2,50})|(fb\.com\/[A-z_0-9\-]{2,50})|(twitter\.com\/[A-z_0-9\-.]{2,40})|(github\.com\/[A-z0-9_-]{1,39})|([A-z0-9_-]{1,39}\.github.(io|com))|(telegram\.me/[A-z_0-9]{5,32})(youtube\.com\/user\/[A-z_0-9\-\.]{2,100})|(linkedin\.com\/company\/[A-z_0-9\.\-]{3,50})|(linkedin\.com\/in\/[A-z_0-9\.\-]{3,50})|(\.?(plus\.google\.com/[A-z0-9_\-.+]{3,255}))|([A-z0-9\-]+\.wordpress\.com)|(reddit\.com/user/[A-z0-9_\-]{3,20})|([A-z0-9\-]{3,32}\.tumblr\.com)|([A-z0-9\-]{3,50}\.blogspot\.com)`

	reg := regexp.MustCompile(netexp)
	found := reg.FindAllString(RESULTS.Pages, -1)
	for _, i := range found {
		if !RESULTS.Networks[i] {
			RESULTS.Networks[i] = true
		}
	}
}

// Return true if the URL matched with the urlExclude option
func urlExcluding(uri string) bool {
	if OPTIONS.URLExcludeRegex.MatchString(uri) {
		return true
	}
	return false
}

// Return true if the status code matched with the codeExclude option
func statusCodeExcluding(code int) bool {
	reg := regexp.MustCompile(OPTIONS.StatusCodeExclude)
	if reg.MatchString(strconv.Itoa(code)) {
		return true
	}
	return false
}

// Send the request and gives the source, status code and errors
func request(uri string) (string, int, error) {
	client := &http.Client{
		Timeout: time.Duration(OPTIONS.Timeout) * time.Second}
	Httptransport := &http.Transport{}
	if OPTIONS.Proxy != "" {
		proxy, err := url.Parse(OPTIONS.Proxy)
		if err != nil {
			logger(err)
			return "", 0, err
		}
		Httptransport.Proxy = http.ProxyURL(proxy)
	}
	if OPTIONS.IgnoreInvalidSSL == true {
		Httptransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client = &http.Client{Transport: Httptransport}
	req, err := http.NewRequest("GET", trim(uri), nil)
	if err != nil {
		logger(err)
		return "", 0, err
	}
	headers := strings.Split(trim(VIEWS_OBJ["HEADERS"].Buffer()), "\n")
	for _, v := range headers {
		kv := strings.Split(v, ": ")
		kv[0] = strings.Replace(kv[0], " ", "", -1)
		req.Header.Set(kv[0], kv[1])
	}
	resp, err := client.Do(req)
	if err != nil {
		logger(err)
		return "", 0, err
	}
	defer resp.Body.Close()
	Body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger(err)
		return "", 0, err
	}
	return string(Body), resp.StatusCode, err
}

// Find the archive pages from the web.archive.org and sanitize
// the URLs and return a list of URLs
func crawlWayBackURLs() []string {
	// Fetch waybackurls need almost 15s timeout
	timeout := OPTIONS.Timeout
	OPTIONS.Timeout = 15
	text, _, ok := request(fmt.Sprintf("%s://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey", OPTIONS.Scheme, PROJECT_NAME))
	OPTIONS.Timeout = timeout
	if ok != nil {
		return []string{}
	}
	var wrapper [][]string
	ok = json.Unmarshal([]byte(text), &wrapper)
	if ok != nil {
		logger(ok)
		return []string{}
	}
	var wayURLs []string
	var code int
	for _, urls := range wrapper[1:] {
		code, _ = strconv.Atoi(urls[4])
		// Exclude the urls with codeExclude and urlExclude
		if statusCodeExcluding(code) && urlExcluding(urls[2]) {
			parse, ok := url.Parse(urls[2])
			if ok != nil {
				continue
			}
			parse.Host = regexp.MustCompile(`:[\d]+`).ReplaceAllString(parse.Host, "")
			marshal, ok := parse.MarshalBinary()
			if ok != nil {
				logger(ok)
				continue
			}
			url := fmt.Sprintf("%s", marshal)
			wayURLs = append(wayURLs, strings.ReplaceAll(url, `\/\/`, `//`))
		}
	}
	return wayURLs
}

// Crawling the robots.txt URLs as seed
func crawlRobots() []string {
	text, statusCode, ok := request(fmt.Sprintf("%s://%s/robots.txt", OPTIONS.Scheme, PROJECT_NAME))
	if ok != nil {
		return []string{}
	}
	if statusCode == 200 {
		var reg *regexp.Regexp
		makers := []string{}
		// It finds all of URLs without any restrict
		for _, obj := range [3]string{`Disallow: (.*)?`, `Allow: (.*)?`, `Sitemap: (.*)?`} {
			reg = regexp.MustCompile(obj)
			for _, link := range [][]string(reg.FindAllStringSubmatch(text, -1)) {
				makers = append(makers, string(link[1]))
			}
		}
		return makers
	}
	return []string{}
}

// Crawling the sitemap.xml URLs as seed
func crawlSitemap() []string {
	text, statusCode, ok := request(fmt.Sprintf("%s://%s/sitemap.xml", OPTIONS.Scheme, PROJECT_NAME))
	if ok != nil {
		return []string{}
	}
	reg := regexp.MustCompile(`<loc>(.*?)</loc>`)
	if statusCode == 200 {
		founds := reg.FindAllStringSubmatch(text, -1)
		out := []string{}
		for _, v := range founds {
			out = append(out, v[1])
		}
		return out
	}
	return []string{}
}

// Find social networks with regex
func checkPostfix(file string, uri string) bool {
	file = strings.ToLower(file)
	uri = strings.ToLower(uri)
	reg := regexp.MustCompile(`\.` + file + `[^\w]`)
	reg2 := regexp.MustCompile(`\.` + file + `[^\w]?$`)

	if reg.MatchString(uri) || reg2.MatchString(uri) || strings.HasSuffix(uri, "."+file) {
		return true
	}
	return false
}

// Set view properties
func settingViews() {
	VIEWS_ATTRS = map[string]viewAttrs{
		"URL": {
			editor:   &singleLineEditor{gocui.DefaultEditor},
			editable: true,
			frame:    true,
			text:     OPTIONS.URL,
			title:    "URL",
			wrap:     false,
			x0:       func(x int) int { return x - x },
			y0:       func(y int) int { return 0 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return 2 },
		},
		"OPTIONS": {
			editor:   gocui.DefaultEditor,
			editable: true,
			frame:    true,
			text:     optionsCode(),
			title:    "Options",
			wrap:     true,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return 2 },
			x1:       func(x int) int { return x / 2 },
			y1:       func(y int) int { return (y / 2) / 2 },
		},
		"HEADERS": {
			editor:   gocui.DefaultEditor,
			editable: true,
			frame:    true,
			text:     OPTIONS.Headers,
			title:    "HTTP Headers",
			wrap:     true,
			x0:       func(x int) int { return x / 2 },
			y0:       func(y int) int { return (y - y) + 2 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return (y / 2) / 2 },
		},
		"QUERY": {
			editor:   &singleLineEditor{gocui.DefaultEditor},
			editable: true,
			frame:    true,
			text:     OPTIONS.Query,
			title:    "Query",
			wrap:     false,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return (y / 2) / 2 },
			x1:       func(x int) int { return x / 2 },
			y1:       func(y int) int { return ((y / 2) / 2) + 2 },
		},
		"REGEX": {
			editor:   &singleLineEditor{gocui.DefaultEditor},
			editable: true,
			frame:    true,
			text:     OPTIONS.RegexString,
			title:    "Regex",
			wrap:     false,
			x0:       func(x int) int { return x / 2 },
			y0:       func(y int) int { return (y / 2) / 2 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return ((y / 2) / 2) + 2 },
		},
		"RESPONSE": {
			editor:   &responseEditor{gocui.DefaultEditor},
			editable: true,
			frame:    true,
			title:    "Response",
			wrap:     true,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return (y/2)/2 + 2 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return y - 4 },
		},
		"STATUS_LINE": {
			editor:   nil,
			editable: false,
			frame:    true,
			wrap:     true,
			text:     STATUS_LINE_NAME,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return y - 4 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return y - 2 },
		},
		"SEARCH": {
			editor:   nil,
			editable: false,
			text:     "search>",
			frame:    false,
			wrap:     false,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return y - 2 },
			x1:       func(x int) int { return 8 },
			y1:       func(y int) int { return y },
		},
		"SEARCH_PROMPT": {
			editor:   &singleLineEditor{&searchEditor{gocui.DefaultEditor}},
			editable: true,
			frame:    false,
			wrap:     false,
			x0:       func(x int) int { return 8 },
			y0:       func(y int) int { return y - 2 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return y },
		},
		"ERROR": {
			editor:   nil,
			editable: false,
			text:     "Terminal is too small",
			title:    "Error",
			frame:    true,
			wrap:     false,
			x0:       func(x int) int { return 0 },
			y0:       func(y int) int { return 0 },
			x1:       func(x int) int { return x - 1 },
			y1:       func(y int) int { return y - 1 },
		},
		"SAVE": {
			editor:   &singleLineEditor{gocui.DefaultEditor},
			editable: true,
			text:     "Terminal is too small",
			title:    "Filename (Enter to submit, Ctrl+q to close)",
			frame:    true,
			wrap:     false,
			x0:       func(x int) int { return (x / 2) / 2 },
			y0:       func(y int) int { return y/2 - 1 },
			x1:       func(x int) int { return x - ((x / 2) / 2) },
			y1:       func(y int) int { return y/2 + 1 },
		},
		"SAVE_RESULT": {
			editor:   nil,
			editable: false,
			title:    "Result save(Ctrl+q to close)",
			frame:    true,
			wrap:     false,
			x0:       func(x int) int { return (x / 2) / 2 },
			y0:       func(y int) int { return (y / 2) + 1 },
			x1:       func(x int) int { return x - ((x / 2) / 2) },
			y1:       func(y int) int { return (y / 2) + 3 },
		},
		"LOADER": {
			editor:   nil,
			editable: false,
			text:     "Loading...",
			frame:    true,
			wrap:     false,
			x0:       func(x int) int { return (x / 2) - 5 },
			y0:       func(y int) int { return (y / 2) + 1 },
			x1:       func(x int) int { return ((x / 2) + 6) },
			y1:       func(y int) int { return (y / 2) + 3 },
		},
	}
}

// Put the msg to the Response View concurrently
func putting(v *gocui.View, msg string) {
	PROG.Gui.Update(func(_ *gocui.Gui) error {
		fmt.Fprintln(v, msg)
		return nil
	})
}

// Push msg to the Response View
func pushing(msg string, err int) {
	if err == 1 {
		logger(&errorString{msg})
	}
	fmt.Fprintln(VIEWS_OBJ["RESPONSE"], msg)
}

func logger(err error) {
	if OPTIONS.Logger != "" && err != nil{
		text := fmt.Sprintf("%v", err)
		ERRORS_STACK = append(ERRORS_STACK, text)
		if toBool(LOGGER_FILE_FLAG) {
			LOGGER_FILE.WriteString(fmt.Sprintf("%s\n", text))
		}
	}
}

func prepareLogger(){
	if OPTIONS.Logger != "" {
		file, err := os.Create(OPTIONS.Logger)
		if err != nil {
			logger(err)
		}
		LOGGER_FILE = file
		LOGGER_FILE_FLAG = 1
	}
}

// Return the difference of the start time to now
func sinceTime() float64 {
	return time.Since(START_TIME).Seconds()
}

// Refresh the status line with new value
func refStatusLine(msg string) {
	VIEWS_OBJ["STATUS_LINE"].Clear()
	putting(VIEWS_OBJ["STATUS_LINE"], STATUS_LINE_NAME+" "+msg)
}

// Show the loading pop-up view
func loading() error {
	X, Y := PROG.Gui.Size()
	attrs := VIEWS_ATTRS["LOADER"]
	if v, err := PROG.Gui.SetView("LOADER", attrs.x0(X), attrs.y0(Y), attrs.x1(X), attrs.y1(Y)); err != nil {
		if err != gocui.ErrUnknownView {
			logger(err)
			return err
		}
		setViewAttrs(v, attrs)
	}
	return nil
}

// parseOptions parses the command line flags provided by a user
func parseOptions() {
	flag.StringVar(&OPTIONS.URL, "url", "", "URL to crawl for")
	flag.IntVar(&OPTIONS.Thread, "thread", 5, "The number of concurrent goroutines for resolving")
	flag.IntVar(&OPTIONS.Delay, "delay", 0, "Sleep between each request(Millisecond)")
	flag.IntVar(&OPTIONS.Timeout, "timeout", 10, "Seconds to wait before timing out")
	flag.IntVar(&OPTIONS.MaxRegexResult, "max-regex", 1000, "Max result of regex search for regex field")
	flag.BoolVar(&OPTIONS.Robots, "robots", false, "Scrape robots.txt for URLs and using them as seeds")
	flag.BoolVar(&OPTIONS.Sitemap, "sitemap", false, "Scrape sitemap.xml for URLs and using them as seeds")
	flag.BoolVar(&OPTIONS.WayBack, "wayback", false, "Scrape WayBackURLs(web.archive.org) for URLs and using them as seeds")
	flag.BoolVar(&OPTIONS.IgnoreInvalidSSL, "Ignore-SSL", false, "Ignore invalid SSL")
	flag.StringVar(&OPTIONS.Query, "query", "", `Query expression(It could be a file extension(pdf), a key query(url,script,css,..) or a jquery selector($("a[class='hdr']).attr('hdr')")))`)
	flag.StringVar(&OPTIONS.Proxy, "proxy", "", "Proxy by scheme://ip:port")
	flag.StringVar(&OPTIONS.Headers, "header", "", "HTTP Header for each request(It should to separated fields by \\n). e.g KEY: VALUE\\nKEY1: VALUE1")
	flag.StringVar(&OPTIONS.RegexString, "regex", "", "Search the Regular Expression on the pages")
	flag.StringVar(&OPTIONS.Logger, "logger", "", "Log errors in a file")
	flag.StringVar(&OPTIONS.Scheme, "scheme", "https", "Set the scheme for the requests")
	flag.IntVar(&OPTIONS.Depth, "depth", 1, "Scraper depth search level")
	flag.StringVar(&OPTIONS.URLExclude, "url-exclude", ".*", "Exclude URLs matching with this regex")
	flag.StringVar(&OPTIONS.StatusCodeExclude, "code-exclude", ".*", "Exclude HTTP status code with these codes. Separate whit '|'")
	flag.StringVar(&OPTIONS.InScopeExclude, "domain-exclude", "", "Exclude in-scope domains to crawl. Separate with comma | default=root domain")
	flag.Parse()
	if OPTIONS.URL != "" {
		OPTIONS.URL = urlSanitize(OPTIONS.URL)
	} else {
		OPTIONS.URL = "https://"
	}
	if !toBool(OPTIONS.Headers) {
		OPTIONS.Headers = `User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0`
	}
}

// Return the options to the option view as text
func optionsCode() string {
	B2S := func(b bool) string {
		if b == true {
			return "true"
		}
		return "false"
	}
	return fmt.Sprintf("thread,depth,delay,timeout,maxRegexResult=%d,%d,%d,%d,%d\nrobots,sitemap,wayback=%s,%s,%s\nlogger=%s\nurlExclude=%s\ncodeExclude=%s\ndomainExclude=%s\nproxy=%s\nIgnoreInvalidSSL=%s",
		OPTIONS.Thread, OPTIONS.Depth, OPTIONS.Delay, OPTIONS.Timeout, OPTIONS.MaxRegexResult,
		B2S(OPTIONS.Robots), B2S(OPTIONS.Sitemap), B2S(OPTIONS.WayBack), OPTIONS.Logger, OPTIONS.URLExclude,
		OPTIONS.StatusCodeExclude, OPTIONS.InScopeExclude, OPTIONS.Proxy, B2S(OPTIONS.IgnoreInvalidSSL))
}

// Read the options from the option View and set them
func prepareOptions() string {
	S2B := func(v string) bool {
		if v == "true" {
			return true
		}
		return false
	}
	code := trim(VIEWS_OBJ["OPTIONS"].Buffer())
	if !toBool(code) {
		return "Options are incomplete. Press Ctrl+R to rewrite options."
	}
	for k, line := range strings.Split(code, "\n") {
		split := strings.Split(line, "=")
		values := strings.Join(split[1:], "=")
		splited := strings.Split(values, ",")
		// If count of the variables doesn't match with values
		if len(splited) != len(strings.Split(split[0], ",")) {
			return "Options are incomplete: All int and bool options must be set. Press Ctrl+R to rewrite options."
		}
		switch k {
		// Set the int variables
		case 0:
			var k int
			var v *int
			for k, v = range []*int{&OPTIONS.Thread, &OPTIONS.Depth, &OPTIONS.Delay, &OPTIONS.Timeout, &OPTIONS.MaxRegexResult} {
				if i, err := strconv.Atoi(splited[k]); err == nil {
					*v = i
				} else {
					return fmt.Sprintf("Invalid value for type int: %s.", splited[k])
				}
			}
		// Set the boolean variables
		case 1:
			OPTIONS.Robots, OPTIONS.Sitemap, OPTIONS.WayBack = S2B(splited[0]), S2B(splited[1]), S2B(splited[2])
		// Set the urlExclude,.. variables
		case 2:
			OPTIONS.Logger = values 
		case 3:
			OPTIONS.URLExclude = values
		case 4:
			OPTIONS.StatusCodeExclude = values
		case 5:
			OPTIONS.InScopeDomains = strings.Split(values, ",")
		case 6:
			OPTIONS.Proxy = values
		case 7:
			OPTIONS.IgnoreInvalidSSL = S2B(values)
		}
	}
	// Prepare the URLs channel for crawl
	TOKENS = make(chan struct{}, OPTIONS.Thread)
	// Init Headers
	OPTIONS.Headers = trim(VIEWS_OBJ["HEADERS"].Buffer())
	prepareQuery()
	return ""
}

// Split the keys as slice and write to the OPTIONS.Keys
func prepareQuery() {
	q := trim(VIEWS_OBJ["QUERY"].Buffer())
	if !strings.HasPrefix(q, "$") {
		OPTIONS.Keys = strings.Split(q, ",")
	} else {
		OPTIONS.Query = q
	}
}

// Return the false if the arg is blank and true if it isn't.
// Supported types: int, string, bool, []int, []string, []bool
func toBool(arg interface{}) bool {
	switch arg.(type) {
	case int:
		return arg != 0
	case string:
		return arg != ""
	case bool:
		return arg == true
	case rune:
		return true
	default:
		tostr, ok := arg.([]string)
		if ok {
			return toBool(len(tostr))
		}
		toint, ok := arg.([]int)
		if ok {
			return toBool(len(toint))
		}
		toflag, ok := arg.([]bool)
		if ok {
			return toBool(len(toflag))
		}
	}
	return false
}

// Print the slices
func slicePrint(head string, s []string) {
	pushing(head, 0)
	for v := range s {
		pushing(s[v], 1)
	}
}

// Print the maps
func mapPrint(head string, m map[string]bool) {
	pushing(head, 0)
	for k := range m {
		pushing(fmt.Sprintf("    %s", k), 0)
	}
}

// Search a key to the list and return the true if it is
func sliceSearch(list *[]string, i string) bool {
	for _, v := range *list {
		if v == i {
			return true
		}
	}
	return false
}

// Search the regex on the web pages and show the result on the Response view
func regexSearch() {
	loading()
	PROG.Gui.Update(func(_ *gocui.Gui) error {
		vrb := VIEWS_OBJ["RESPONSE"]
		vrb.Clear()
		if RESULTS != nil {
			for k, v := range RESULTS.PageByURL {
				founds := OPTIONS.Regex.FindAllString(v, OPTIONS.MaxRegexResult)
				// Print page address and len of results
				pushing(fmt.Sprintf(" > %s | %d", k, len(founds)), 0)
				if founds != nil {
					for _, v := range founds {
						pushing("     > " + v, 0)
					}
				}
			}
		}
		PROG.currentPage = vrb.Buffer()
		PROG.Gui.DeleteView("LOADER")
		return nil
	})
}

// Gives a query($("a").attr("href")) and return the result of query
func parseQuery(query string) ([]string, string) {
	query = strings.TrimSpace(query)
	// Extract the expressions
	syntaxExp := regexp.MustCompile(`^\$\("([^"]+)"\)\.([\w]+)\(("([^"]+)")?\)`).FindAllStringSubmatch(query, 1)
	outputResult := []string{}
	// Check the syntax of query
	if !toBool(len(syntaxExp)) {
		return outputResult, "Query: Invalid syntax"
	}
	query = strings.ReplaceAll(query, syntaxExp[0][0], "")
	exprs := syntaxExp[0][1:]
	// Check the method names
	methods := []string{"html", "text", "attr"}
	method := exprs[1]
	if !sliceSearch(&methods, method) {
		return outputResult, "Query: Invalid method name"
	}
	// Read the document to parse
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(RESULTS.Pages))
	if err != nil {
		return outputResult, fmt.Sprintf("%s", err)
	}
	var def func(*goquery.Selection) (string, error)
	switch method {
	case "text":
		def = func(obj *goquery.Selection) (string, error) {
			return obj.Text(), nil
		}
	case "html":
		def = func(obj *goquery.Selection) (string, error) {
			return obj.Html()
		}
	case "attr":
		def = func(obj *goquery.Selection) (string, error) {
			attr, _ := obj.Attr(exprs[3])
			return attr, nil
		}
	}
	// Run the query
	doc.Find(exprs[0]).Each(func(i int, obj *goquery.Selection) {
		rsp, err := def(obj)
		if err == nil {
			outputResult = append(outputResult, rsp)
		} else {
			logger(err)
		}
	})
	return outputResult, ""
}

// Trim the spaces
func trim(s string) string {
	return strings.TrimSpace(s)
}

// If the i is not in the list uniq append i to the slice
func uniq(list *[]string, i string) {
	is := true
	for _, v := range *list {
		if v == i {
			is = false
		}
	}
	if is {
		*list = append(*list, i)
	}
}

// Identify the Out Scope URLs
func isOutScope(host string) bool {
	host = strings.ToLower(host)
	host = strings.Replace(host, "www.", ".", 1)
	sh := strings.Split(strings.ToLower(PROJECT_NAME), ".")
	var suffix string
	if len(sh) > 1 {
		suffix = "." + sh[len(sh)-2] + "." + sh[len(sh)-1]
	} else {
		suffix = "." + PROJECT_NAME
	}
	if !strings.HasSuffix(host, suffix) && !sliceSearch(&OPTIONS.InScopeDomains, host) {
		return true
	}
	return false
}

// A URL joiner
func urjoin(baseurl, uri string) string {
	urlower := strings.ToLower(uri)
	baseurl = strings.ReplaceAll(baseurl, `\/\/`, `//`)
	var pos int
	for _, v := range []string{" ", "", "/", "#", "http://", "https://"} {
		if urlower == v {
			return ""
		}
	}
	// remove the spaces
	pos = strings.Index(uri, " ")
	if pos > -1 {
		uri = uri[:pos]
	}
	// remove the user@.. portion
	pos = strings.Index(uri, "@")
	if pos > -1 {
		uri = uri[:pos]
	}
	// remove the comments
	pos = strings.Index(uri, "#")
	if pos > -1 {
		uri = uri[:pos]
	}
	if !strings.HasSuffix(baseurl, "/") {
		baseurl = baseurl + "/"
	}
	if strings.HasPrefix(uri, "://") {
		return ""
	}
	if strings.HasPrefix(uri, "//") {
		return baseurl + uri
	}
	if strings.HasPrefix(uri, "/") {
		return baseurl + uri[1:]
	}
	base, err := url.Parse(baseurl)
	if err != nil {
		logger(err)
		return ""
	}
	final, err := base.Parse(uri)
	if err != nil {
		logger(err)
		return ""
	}
	return final.String()
}

// Remove URL scheme and replace it with default scheme and
// removes last slash
func setURLUniq(uri string) string {
	// Set Scheme
	uri = regexp.MustCompile(`https?://`).ReplaceAllString(uri, OPTIONS.Scheme+"://")
	// Remove last slash
	uri = regexp.MustCompile(`/$`).ReplaceAllString(uri, "")
	return uri
}

// Setting the URL Scheme
func urlSanitize(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		logger(err)
		// ://name.tld/
		uri = OPTIONS.Scheme + uri
		u, err = url.Parse(uri)
		if err != nil {
			logger(err)
			return ""
		}
	}
	if u.Scheme == "" {
		uri = strings.Replace(uri, "://", "", -1)
		uri = fmt.Sprintf("%s://%s", OPTIONS.Scheme, uri) // Default scheme
	}
	return uri
}

/* Identify the type of URL and sanitize the URLs.
Then it returns the URLs that can be scrape. */
func urlCategory(urls []string) []string {
	spool := []string{}
	var join string
	var broke int
	// Sometimes the program is broken with runtime error
	// Then we use Mutex to lock the loop to solve the problem
	MUTEX.Lock()
	defer MUTEX.Unlock()
	for _, link := range urls {
		// If the URL is nothing or blank
		if !toBool(link) {
			continue
		}
		// If the URL is a phone, CDN or email
		if addCDN(link) || addPhone(link) || addEmail(link) {
			continue
		}
		join = urjoin(BASEURL, link)
		if !toBool(join) || !strings.Contains(join, "://") || !strings.Contains(join, ".") {
			continue
		}
		// Identify the media files
		broke = 0
		for _, ext := range MEDIA_POSTFIX {
			if x := checkPostfix(ext, join); x {
				if !RESULTS.Medias[join] {
					RESULTS.Medias[join] = true
				}
				broke = 1
				break
			}
		}
		if broke == 1 {
			continue
		}
		// If it is a JavaScript file
		if checkPostfix("js", join) {
			if !RESULTS.Scripts[join] {
				RESULTS.Scripts[join] = true
			}
			continue
		}
		// If it is a CSS file
		if checkPostfix("css", join) {
			if !RESULTS.CSS[join] {
				RESULTS.CSS[join] = true
			}
			continue
		}
		urparse, err := url.Parse(join)
		if err != nil {
			logger(err)
			continue
		}
		// If the URL is out from scope
		if isOutScope(urparse.Host) {
			if !RESULTS.OutScopeURLs[join] {
				RESULTS.OutScopeURLs[join] = true
			}
			continue
		}
		// Clean the URL
		join = setURLUniq(join)
		if len(urparse.Query()) > 0 {
			RESULTS.QueryURLs[join] = true
		}
		// Add URL to URLs and output URLs
		if !RESULTS.URLs[join] {
			RESULTS.URLs[join] = true
		}
		uniq(&spool, join)
	}
	return spool
}

// Clean the comments from the page source
func removeComments(text string) string {
	reg := regexp.MustCompile(`<!--([\s\S]*?)-->`)
	text = reg.ReplaceAllString(text, ``)
	return text
}

// Identify the Content Delivery Networks
func addCDN(uri string) bool {
	if strings.HasPrefix(uri, "//") && strings.Contains(uri, ".") && len(strings.Split(uri, ".")) >= 2 {
		RESULTS.CDNs[uri] = true
		return true
	}
	return false
}

// Identify the Phone numbers
func addPhone(uri string) bool {
	if strings.HasPrefix(uri, "tel://") {
		RESULTS.Phones[uri[6:]] = true
		return true
	}
	return false
}

// Identify the Email from the URL
func addEmail(uri string) bool {
	if strings.HasPrefix(uri, "mailto:") && strings.Contains(uri, "@") {
		uri = strings.ToLower(strings.Replace(uri[7:], "//", "", -1))
		if strings.Contains(uri, "?") {
			uri = strings.Split(uri, "?")[0]
		}
		RESULTS.Emails[uri] = true
		return true
	}
	return false
}

// Search prompt regex
func responseSearch() error {
	vrb := VIEWS_OBJ["RESPONSE"]
	vrb.Clear()
	expr := strings.TrimSpace(VIEWS_OBJ["SEARCH_PROMPT"].Buffer())
	if expr == "" {
		pushing(PROG.currentPage, 0)
		vrb.Title = VIEWS_ATTRS["RESPONSE"].title
		return nil
	}
	reg, err := regexp.Compile(expr)
	if err != nil {
		pushing(fmt.Sprintf("Invalid Regex: %v", err), 1)
		return nil
	}
	results := reg.FindAllString(PROG.currentPage, OPTIONS.MaxRegexResult)
	if len(results) < 1 {
		pushing("No result.", 0)
	}
	vrb.Title = fmt.Sprintf("%d results", len(results))
	for _, v := range results {
		pushing("> " + v, 0)
	}
	return nil
}

// Show the saving pop-up view
func responseSaveView() {
	currentDir, err := os.Getwd()
	if err != nil {
		currentDir = ""
	}
	currentDir += "/"
	PROG.Gui.Update(func(g *gocui.Gui) error {
		X, Y := g.Size()
		attrs := VIEWS_ATTRS["SAVE"]
		if v, err := g.SetView("SAVE", attrs.x0(X), attrs.y0(Y), attrs.x1(X), attrs.y1(Y)); err != nil {
			if err != gocui.ErrUnknownView {
				logger(err)
				return err
			}
			attrs.text = currentDir
			setViewAttrs(v, attrs)
			v.SetCursor(len(currentDir), 0)
		}
		g.SetCurrentView("SAVE")
		return nil
	})
}

// Show the status of output
func saveResultView(res string) {
	if len(res) > 65 {
		res = res[:65] + "..."
		res = "Error: " + res
	}
	PROG.Gui.Update(func(g *gocui.Gui) error {
		X, Y := g.Size()
		attrs := VIEWS_ATTRS["SAVE_RESULT"]
		if v, err := g.SetView("SAVE_RESULT", attrs.x0(X), attrs.y0(Y), attrs.x1(X), attrs.y1(Y)); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			attrs.text = res
			setViewAttrs(v, attrs)
		}
		return nil
	})
}

// Setting View Attributes
func setViewAttrs(v *gocui.View, attrs viewAttrs) *gocui.View {
	v.Title = attrs.title
	v.Frame = attrs.frame
	v.Editable = attrs.editable
	v.Wrap = attrs.wrap
	v.Editor = attrs.editor
	fmt.Fprintf(v, attrs.text)
	return v
}

// Building Views
func layout(g *gocui.Gui) error {
	X, Y := g.Size()
	// If the X and Y is less than minimum(MIN_X,MIN_Y) then it shows the ERROR VIEW
	if X < MIN_X || Y < MIN_Y {
		attrs := VIEWS_ATTRS["ERROR"]
		if v, err := g.SetView("ERROR", attrs.x0(X), attrs.y0(Y), attrs.x1(X), attrs.y1(Y)); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			if _, err := g.SetCurrentView("ERROR"); err != nil {
				return err
			}
			setViewAttrs(v, attrs)
		}
		return nil
	}
	g.DeleteView("ERROR")
	for _, viewName := range ALL_VIEWS {
		attrs := VIEWS_ATTRS[viewName]
		if v, err := g.SetView(viewName, attrs.x0(X), attrs.y0(Y), attrs.x1(X), attrs.y1(Y)); err != nil {
			if err != gocui.ErrUnknownView {
				return err
			}
			if viewName == "URL" {
				if _, err := g.SetCurrentView("URL"); err != nil {
					return err
				}
				v.SetCursor(8, 0)
			}
			setViewAttrs(v, attrs)
			VIEWS_OBJ[viewName] = v
		}
	}
	return nil
}

// Define Keyboard Events
func initKeybindings(g *gocui.Gui) error {
	// To exit from the program: Ctrl+Z
	if err := g.SetKeybinding("", gocui.KeyCtrlZ, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			return gocui.ErrQuit
		}); err != nil {
		return err
	}

	// To save the Response value: Ctrl+S
	if err := g.SetKeybinding("", gocui.KeyCtrlS, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			// Show the save view
			responseSaveView()

			// Save the result with Enter key
			if err := g.SetKeybinding("SAVE", gocui.KeyEnter, gocui.ModNone,
				func(g *gocui.Gui, v *gocui.View) error {
					results := append(VIEWS_OBJ["RESPONSE"].BufferLines(), fmt.Sprintf("\n[Elapsed:%fs] | [Obtained:%d]", sinceTime(), len(RESULTS.URLs))) 
					g.DeleteView("SAVE_RESULT")
					if err := output(results, strings.TrimSpace(v.Buffer())); err != nil {
						saveResultView(fmt.Sprintf("%s", err))
					} else {
						saveResultView("Response saved successfully.")
					}
					return nil
				}); err != nil {
				return err
			}

			// Ctrl+Q to close the save pop-up view
			if err := g.SetKeybinding("SAVE", gocui.KeyCtrlQ, gocui.ModNone,
				func(g *gocui.Gui, v *gocui.View) error {
					g.DeleteView("SAVE")
					g.DeleteView("SAVE_RESULT")
					g.SetCurrentView(VIEWS[PROG.currentPageIndex])
					g.Cursor = true
					return nil
				}); err != nil {
				return err
			}
			return nil
		}); err != nil {
		return err
	}

	// To go to the next view: Tab
	if err := g.SetKeybinding("", gocui.KeyTab, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			PROG.currentPageIndex = (PROG.currentPageIndex + 1) % len(VIEWS)
			g.SetCurrentView(VIEWS[PROG.currentPageIndex])
			return nil
		}); err != nil {
		return err
	}

	// To run the crawler in each view: Ctrl+Space
	if err := g.SetKeybinding("", gocui.KeyCtrlSpace, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			crawlIO()
			return nil
		}); err != nil {
		return err
	}

	// To select the Search Prompt view: Ctrl+F
	if err := g.SetKeybinding("", gocui.KeyCtrlF, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			g.SetCurrentView("SEARCH_PROMPT")
			return nil
		}); err != nil {
		return err
	}

	// To run the crawler in the URL view: Enter
	if err := g.SetKeybinding("URL", gocui.KeyEnter, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			crawlIO()
			return nil
		}); err != nil {
		return err
	}

	// To rewrite the default options from the optionsCode: Ctrl+R
	if err := g.SetKeybinding("OPTIONS", gocui.KeyCtrlR, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			vrb := VIEWS_OBJ["OPTIONS"]
			vrb.Clear()
			fmt.Fprintln(vrb, optionsCode())
			return nil
		}); err != nil {
		return err
	}

	// To rewrite the default headers: Ctrl+R
	if err := g.SetKeybinding("HEADERS", gocui.KeyCtrlR, gocui.ModNone,
		func(g *gocui.Gui, v *gocui.View) error {
			vrb := VIEWS_OBJ["HEADERS"]
			vrb.Clear()
			fmt.Fprintln(vrb, OPTIONS.Headers)
			return nil
		}); err != nil {
		return err
	}

	// To search the entered keys and shows the results: Enter
	if err := g.SetKeybinding("QUERY", gocui.KeyEnter, gocui.ModNone,
		func(_ *gocui.Gui, v *gocui.View) error {
			if RESULTS == nil {
				return nil
			}
			prepareQuery()
			outcomeIO()
			return nil
		}); err != nil {
		return err
	}

	// To search the entered regex in the web pages: Enter
	if err := g.SetKeybinding("REGEX", gocui.KeyEnter, gocui.ModNone,
		func(_ *gocui.Gui, v *gocui.View) error {
			prepareOptions()
			regex := strings.TrimSpace(v.Buffer())
			vrb := VIEWS_OBJ["RESPONSE"]
			PROG.currentPage = vrb.Buffer()
			vrb.Clear()
			// Checking regex
			reg, err := regexp.Compile(regex)
			if err != nil {
				msg := fmt.Sprintf("Invalid Regex: %v", err)
				logger(&errorString{msg})
				fmt.Fprintf(vrb, msg)
				return nil
			}
			OPTIONS.Regex = reg
			regexSearch()
			return nil
		}); err != nil {
		return err
	}
	return nil
}

// Save the slice of data in the path
func output(data []string, path string) error {
	fopen, err := os.Create(path)
	defer fopen.Close()
	if err != nil {
		return err
	}
	for _, v := range data {
		fopen.WriteString(v + "\n")
	}
	return nil
}

// Search prompt editor. It search the regex by event of keys
func (e searchEditor) Edit(v *gocui.View, key gocui.Key, ch rune, mod gocui.Modifier) {
	e.editor.Edit(v, key, ch, mod)
	PROG.Gui.Update(func(g *gocui.Gui) error {
		responseSearch()
		return nil
	})
}

// The singleLineEditor removes multi lines capabilities.
// the Edit function credited from the Wuzz project
func (e singleLineEditor) Edit(v *gocui.View, key gocui.Key, ch rune, mod gocui.Modifier) {
	switch {
	case (ch != 0 || key == gocui.KeySpace) && mod == 0:
		e.editor.Edit(v, key, ch, mod)
		// At the end of the line the default gocui editor adds a whitespace
		// Force him to remove
		ox, _ := v.Cursor()
		if ox > 1 && ox >= len(v.Buffer())-2 {
			v.EditDelete(false)
		}
		return
	case key == gocui.KeyEnter:
		return
	case key == gocui.KeyArrowRight:
		ox, _ := v.Cursor()
		if ox >= len(v.Buffer())-1 {
			return
		}
	case key == gocui.KeyHome || key == gocui.KeyArrowUp:
		v.SetCursor(0, 0)
		v.SetOrigin(0, 0)
		return
	case key == gocui.KeyEnd || key == gocui.KeyArrowDown:
		width, _ := v.Size()
		lineWidth := len(v.Buffer()) - 1
		if lineWidth > width {
			v.SetOrigin(lineWidth-width, 0)
			lineWidth = width - 1
		}
		v.SetCursor(lineWidth, 0)
		return
	}
	e.editor.Edit(v, key, ch, mod)
}

// The singleLineEditor removes multi lines capabilities
func (e responseEditor) Edit(v *gocui.View, key gocui.Key, ch rune, mod gocui.Modifier) {
	if key == gocui.KeyArrowUp || key == gocui.KeyArrowDown {
		e.editor.Edit(v, key, ch, mod)
	}
}

// Find all of href|src attribute values as URL. It's not limited just a[href]
func getURLs(text string) []string {
	text = removeComments(text)
	sanitizeTags := regexp.MustCompile(`<|>|/>`)
	reg := regexp.MustCompile(`(href|src)\s*?=\s*['"](/?.*?)['"]|['"](http.*?)['"]`)
	find := reg.FindAllString(text, -1)
	links := []string{}
	repPrefix := regexp.MustCompile(`(href|src)\s*?=\s*`)
	for _, v := range find {
		if v != "" && !sanitizeTags.MatchString(v) {
			v = repPrefix.ReplaceAllString(v, ``)
			links = append(links, strings.ReplaceAll(strings.ReplaceAll(v, "'", ""), "\"", ""))
		}
	}
	return links
}

// getSource run with each URL and extract links from the URL page
func getSource(uri string) ([]string, error) {
	if !urlExcluding(uri) {
		return []string{}, nil
	}
	time.Sleep(time.Duration(OPTIONS.Delay) * time.Millisecond)
	text, statusCode, err := request(uri)
	if err != nil {
		return []string{}, err
	}
	if !statusCodeExcluding(statusCode) {
		return []string{}, nil
	}
	putting(VIEWS_OBJ["RESPONSE"], " > " + uri)
	RESULTS.Pages += text
	RESULTS.PageByURL[uri] = text
	allURLs := getURLs(text)
	allURLs = urlCategory(allURLs)
	refStatusLine(fmt.Sprintf("[Elapsed:%fs] | [Obtained:%d] | [%s]", sinceTime(), len(RESULTS.URLs), uri))
	return allURLs, nil
}

// Crawling process for each seed
func crawl(uri string) []string {
	TOKENS <- struct{}{}
	list, err := getSource(uri)
	if err != nil {
		return []string{}
	}
	<-TOKENS
	if DEPTH == OPTIONS.Depth {
		return []string{}
	}
	DEPTH += 1
	return list
}

// Run the crawler
func crawlIO() error {
	respObj := VIEWS_OBJ["RESPONSE"]
	// Clear the Response values
	respObj.Clear()
	if err := prepareOptions(); err != "" {
		logger(&errorString{err})
		fmt.Fprintf(respObj, err)
		return nil
	}
	// Start the time
	START_TIME = time.Now()
	// Show loading pop-up
	loading()
	// Prepare the Results
	RESULTS = &Results{"", map[string]string{}, map[string]bool{},
		map[string]bool{}, map[string]bool{}, map[string]bool{},
		map[string]bool{}, map[string]bool{}, map[string]bool{},
		map[string]bool{}, map[string]bool{}, map[string]bool{},
		map[string]bool{}, []string{}, map[string][]string{}}
	// Prepare logger
	prepareLogger()
	go func() error {
		defer PROG.Gui.Update(func(g *gocui.Gui) error {
			g.DeleteView("LOADER")
			// Refresh the status line. the status line shows the elapsed time as second and obtained URLs
			fmt.Fprintln(VIEWS_OBJ["STATUS_LINE"],
				fmt.Sprintf("%s [Elapsed:%fs] | [Obtained:%d] | [Status:Done]",
					STATUS_LINE_NAME, sinceTime(), len(RESULTS.URLs)))
			return nil
		})
		urparse, err := url.Parse(trim(VIEWS_OBJ["URL"].Buffer()))
		if err != nil {
			pushing(fmt.Sprintf("Invalid URL: %v", err), 1)
			return nil
		}
		// Checking urlExclude option
		OPTIONS.URLExcludeRegex, err = regexp.Compile(OPTIONS.URLExclude)
		if err != nil {
			pushing(fmt.Sprintf("Invalid url_exclude regex: %v", err), 1)
			return nil
		}
		// Checking codeExclude option
		OPTIONS.StatusCodeRegex, err = regexp.Compile(OPTIONS.StatusCodeExclude)
		if err != nil {
			pushing(fmt.Sprintf("Invalid code_exclude regex: %v", err), 1)
			return nil
		}
		PROJECT_NAME = strings.Replace(urparse.Host, "www.", "", -1)
		OPTIONS.Scheme = urparse.Scheme
		OPTIONS.InScopeDomains = append(OPTIONS.InScopeDomains, PROJECT_NAME)
		BASEURL = urlSanitize(PROJECT_NAME)
		worklist := make(chan []string)
		var n int // number of pending sends to worklist
		// Start with the URL argument.
		n++
		seen := make(map[string]bool)
		seen[urparse.String()] = true

		seeds, err := getSource(urparse.String())
		if err != nil {
			pushing(fmt.Sprintf("Request: %v", err), 0)
			return nil
		}
		anseeds := []string{}
		if OPTIONS.Robots {
			anseeds = crawlRobots()
		}
		if OPTIONS.Sitemap {
			anseeds = append(anseeds, crawlSitemap()...)
		}
		if OPTIONS.WayBack {
			anseeds = append(anseeds, crawlWayBackURLs()...)
		}
		if OPTIONS.Depth > 1 {
			seeds = append(seeds, urlCategory(anseeds)...)
		} else {
			urlCategory(anseeds)
			PROG.currentPage = respObj.Buffer()
			return nil
		}
		PROG.Gui.Update(func(g *gocui.Gui) error {
			g.DeleteView("LOADER")
			return nil
		})
		go func() { worklist <- seeds }()
		// Crawl the web concurrently
		for ; n > 0; n-- {
			list := <-worklist
			for _, link := range list {
				link = setURLUniq(urjoin(BASEURL, link))
				// Means don't crawl a link twice
				if !seen[link] {
					seen[link] = true
					n++
					// Add seeds to worklist
					go func(link string) {
						worklist <- crawl(link)
					}(link)
				}
			}
		}
		return nil
	}()
	PROG.currentPage = respObj.Buffer()
	return nil
}

/* outcomeIO gives the Keys from Keys Field and
shows the results.
keys could be pre-define(ALL_KEYS) options or a
file extension like docx. */
func outcomeIO() {
	vrb := VIEWS_OBJ["RESPONSE"]
	vrb.Clear()
	loading()
	vrb.SetOrigin(0, 0)

	PROG.Gui.Update(func(_ *gocui.Gui) error {
		defer PROG.Gui.DeleteView("LOADER")
		// If it is a JQuery syntax
		if strings.HasPrefix(OPTIONS.Query, "$") {
			resp, err := parseQuery(OPTIONS.Query)
			if err != "" {
				pushing(err, 1)
				return nil
			}
			slicePrint(fmt.Sprintf("[*] %s | %d", OPTIONS.Query, len(resp)), resp)
		} else {

			var ext2 bool
			for _, q := range OPTIONS.Keys {
				ext2 = q == "all"

				if q == "email" || ext2 {
					findEmails()
					mapPrint(fmt.Sprintf("[*] Emails | %d", len(RESULTS.Emails)), RESULTS.Emails)
				}
				if q == "comment" || ext2 {
					findComments()
					mapPrint(fmt.Sprintf("[*] Comments | %d", len(RESULTS.Comments)), RESULTS.Comments)
				}
				if q == "url" || ext2 {
					mapPrint(fmt.Sprintf("[*] In Scope URLs | %d", len(RESULTS.URLs)), RESULTS.URLs)
				}
				if q == "all_urls" || ext2 {
					mapPrint(fmt.Sprintf("[*] Out Scope URLs | %d", len(RESULTS.OutScopeURLs)), RESULTS.OutScopeURLs)
				}
				if q == "cdn" || ext2 {
					mapPrint(fmt.Sprintf("[*] CDNs | %d", len(RESULTS.CDNs)), RESULTS.CDNs)
				}
				if q == "script" || ext2 {
					mapPrint(fmt.Sprintf("[*] Scripts | %d", len(RESULTS.Scripts)), RESULTS.Scripts)
				}
				if q == "css" || ext2 {
					mapPrint(fmt.Sprintf("[*] CSS | %d", len(RESULTS.CSS)), RESULTS.CSS)
				}
				if q == "media" || ext2 {
					mapPrint(fmt.Sprintf("[*] Media | %d", len(RESULTS.Medias)), RESULTS.Medias)
				}
				if q == "dns" || ext2 {
					findHostnames()
					slicePrint(fmt.Sprintf("[*] HostNames | %d", len(RESULTS.HostNames)), RESULTS.HostNames)
				}
				if q == "network" || ext2 {
					findNetworks()
					mapPrint(fmt.Sprintf("[*] Social Networks | %d", len(RESULTS.Networks)), RESULTS.Networks)
				}
				if q == "query_urls" || ext2 {
					mapPrint(fmt.Sprintf("[*] Get URLs | %d", len(RESULTS.QueryURLs)), RESULTS.QueryURLs)
				}
				if q == "phones" || ext2 {
					mapPrint(fmt.Sprintf("[*] Phones | %d", len(RESULTS.Phones)), RESULTS.Phones)
				}
				if !sliceSearch(&ALL_KEYS, q) {
					var medias []string
					for k := range RESULTS.Medias {
						if checkPostfix(q, k) {
							medias = append(medias, k)
						}
					}
					slicePrint(fmt.Sprintf("[*] '%s' | %d", q, len(medias)), medias)
				}
			}
		}
		PROG.currentPage = vrb.Buffer()
		return nil
	})
}

// The main function
func main() {
	parseOptions()
	var g *gocui.Gui
	var err error
	// Create a new GUI
	for _, outputMode := range []gocui.OutputMode{gocui.Output256, gocui.OutputNormal} {
		g, err = gocui.NewGui(outputMode)
		if err == nil {
			break
		}
	}
	if err != nil {
		fmt.Println(err)
	}
	defer g.Close()
	g.Cursor = true
	VIEWS_OBJ = map[string]*gocui.View{}
	g.SetManagerFunc(layout)
	// Initialize kayboard Events
	if err := initKeybindings(g); err != nil {
		fmt.Println(err)
	}
	// If the OS is windows. it use the Ascii chars
	if runtime.GOOS == "windows" {
		g.ASCII = true
	}
	PROG = def{"", 0, g}
	// Build the Views
	settingViews()
	// Run the Main Loop
	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		fmt.Println(err)
	}
}
