package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
	"github.com/gorilla/mux"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
}

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type CrawledUrl struct {
	Url       string    `json:"url"`
	Content   string    `json:"content"`
	Links     []string  `json:"links"`
	BaseUrl   string    `json:"baseUrl"`
	FoundAt   time.Time `json:"foundAt"`
	IsCrawled bool      `json:"isCrawled"`
}

type CrawlHistory struct {
	Username    string       `json:"username"`
	CrawledUrls []CrawledUrl `json:"crawledUrls"`
}

var users = make(map[string]User) // In-memory user store for simplicity
var crawlHistories = make(map[string]CrawlHistory)

// Random User Agent seçimi
func randomUserAgent() string {
	rand.Seed(time.Now().Unix())
	randNum := rand.Int() % len(userAgents)
	return userAgents[randNum]
}

// HTTP Get Request Fonksiyonu
func getRequest(targetUrl string) (*http.Response, error) {
	client := &http.Client{}

	req, _ := http.NewRequest("GET", targetUrl, nil)
	req.Header.Set("User-Agent", randomUserAgent())

	res, err := client.Do(req)

	if err != nil {
		return nil, err
	} else {
		return res, nil
	}
}

// Sayfada bulunan linkleri bulma
func discoverLinks(response *http.Response, baseURL string) []string {
	if response != nil {
		doc, _ := goquery.NewDocumentFromResponse(response)
		foundUrls := []string{}
		if doc != nil {
			doc.Find("a").Each(func(i int, s *goquery.Selection) {
				res, _ := s.Attr("href")
				foundUrls = append(foundUrls, res)
			})
		}
		return foundUrls
	} else {
		return []string{}
	}
}

// Relative linkleri kontrol etme
func checkRelative(href string, baseUrl string) string {
	if strings.HasPrefix(href, "/") {
		return fmt.Sprintf("%s%s", baseUrl, href)
	} else {
		return href
	}
}

// Relative linkleri çözme
func resolveRelativeLinks(href string, baseUrl string) (bool, string) {
	resultHref := checkRelative(href, baseUrl)
	baseParse, _ := url.Parse(baseUrl)
	resultParse, _ := url.Parse(resultHref)
	if baseParse != nil && resultParse != nil {
		if baseParse.Host == resultParse.Host {
			return true, resultHref
		} else {
			return false, ""
		}
	}
	return false, ""
}

// Token bazlı sınırlama
var tokens = make(chan struct{}, 5) // Channel working as a semaphore - using 5 or more tokens likely to overload target site

// Crawl Fonksiyonu
func Crawl(username, targetURL string) []string {
	color.Cyan("Crawl edilen link: %s", targetURL)
	tokens <- struct{}{}
	resp, _ := getRequest(targetURL)
	<-tokens
	links := discoverLinks(resp, targetURL)
	color.Green("Bulunan linkler:")
	for _, link := range links {
		color.Green(link)
	}
	foundUrls := []string{}
	for _, link := range links {
		ok, correctLink := resolveRelativeLinks(link, targetURL)
		if ok {
			if correctLink != "" {
				foundUrls = append(foundUrls, correctLink)
				color.Yellow("Sıraya eklenen link: %s", correctLink)
			}
		}
	}
	parsedHTML := ParseHTML(resp, targetURL)
	saveToUserHistory(username, parsedHTML)
	return foundUrls
}

// Sayfa içeriğini hashleme
func hashContent(content string) string {
	salt := "somerandomsalt"
	hash := sha256.Sum256([]byte(content + salt))
	return hex.EncodeToString(hash[:])
}

// Sayfa içeriğini JSON olarak kaydetme
func saveToJson(crawledUrl CrawledUrl) {
	file, err := os.OpenFile("urls.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	data, err := json.MarshalIndent(crawledUrl, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling to JSON:", err)
		return
	}
	if _, err := file.Write(data); err != nil {
		fmt.Println("Error writing to file:", err)
	}
}

// Kullanıcı tarama geçmişini kaydetme
func saveToUserHistory(username string, crawledUrl CrawledUrl) {
	history, exists := crawlHistories[username]
	if !exists {
		history = CrawlHistory{Username: username, CrawledUrls: []CrawledUrl{}}
	}
	history.CrawledUrls = append(history.CrawledUrls, crawledUrl)
	crawlHistories[username] = history
}

// HTML içeriğini işleme ve kaydetme
func ParseHTML(response *http.Response, targetUrl string) CrawledUrl {
	if response != nil {
		bodyBytes, _ := ioutil.ReadAll(response.Body)
		bodyString := string(bodyBytes)
		hashedContent := hashContent(bodyString)
		foundAt := time.Now()
		crawledUrl := CrawledUrl{
			Url:       targetUrl,
			Content:   hashedContent,
			Links:     discoverLinks(response, targetUrl),
			BaseUrl:   targetUrl,
			FoundAt:   foundAt,
			IsCrawled: true,
		}
		saveToJson(crawledUrl)
		return crawledUrl
	}
	return CrawledUrl{}
}

// URL'nin doğru formatta olup olmadığını kontrol etme
func validateUrl(inputUrl string) string {
	if !strings.HasPrefix(inputUrl, "http://") && !strings.HasPrefix(inputUrl, "https://") {
		return "http://" + inputUrl
	}
	return inputUrl
}

// Kullanıcı kayıt işlemi
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, exists := users[newUser.Username]; exists {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}
	users[newUser.Username] = newUser
	w.WriteHeader(http.StatusCreated)
}

// Kullanıcı giriş işlemi
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials User
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user, exists := users[credentials.Username]
	if !exists || user.Password != credentials.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Tarama işlemi
func crawlHandler(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		URL      string `json:"url"`
		Username string `json:"username"`
	}
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	requestBody.URL = validateUrl(requestBody.URL)
	foundLinks := Crawl(requestBody.Username, requestBody.URL)
	response, err := json.Marshal(foundLinks)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// Kullanıcı tarama geçmişi
func historyHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	history, exists := crawlHistories[username]
	if !exists {
		http.Error(w, "No history found for user", http.StatusNotFound)
		return
	}
	response, err := json.Marshal(history)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/crawl", crawlHandler).Methods("POST")
	r.HandleFunc("/history", historyHandler).Methods("GET")
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	fmt.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
