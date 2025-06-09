package golangIPSentry

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (i *IPGuardian) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		check := i.Check(c.Request, c.Writer)
		if !check.Success {
			c.JSON(check.StatusCode, gin.H{
				"error": check.Error,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (i *IPGuardian) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		check := i.Check(r, w)

		if !check.Success {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(check.StatusCode)
			json.NewEncoder(w).Encode(map[string]string{
				"error": check.Error,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
