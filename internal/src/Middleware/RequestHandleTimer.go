package middleware

import (
	"log"
	"net/http"
	"time"
)

func RequestHandleTimer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startAt := time.Now().UnixNano()

		next.ServeHTTP(w, r)

		endAt := time.Now().UnixNano()
		log.Printf("Duration = " + time.Duration(endAt-startAt).String())
	})
}
